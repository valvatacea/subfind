"""Session store untuk bot: persist state per-scan ke SQLite (Fase 0).

Modul ini sengaja TIDAK mengubah perilaku bot. Hanya menyediakan
schema + CRUD + cache in-memory. Fase 1+ akan mulai memakainya.
"""
import os
import json
import sqlite3
import threading
import time
import uuid
import logging

log = logging.getLogger('surfinder.session_store')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, 'output', 'state.db')

_lock = threading.RLock()
_conn = None
_db_path = None

# Cache in-memory (hot path) — sid -> dict
_cache = {}
_cache_lock = threading.RLock()
_CACHE_MAX = 128


def _now():
    return int(time.time())


def init_db(db_path=None):
    """Buat tabel jika belum ada. Idempotent. Panggil sekali saat startup."""
    global _conn, _db_path
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with _lock:
        if _conn is not None:
            return _conn
        conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA synchronous = NORMAL')
        conn.execute('PRAGMA busy_timeout = 5000')
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS sessions (
            id            TEXT PRIMARY KEY,
            chat_id       INTEGER NOT NULL,
            mode          TEXT NOT NULL,
            status        TEXT NOT NULL,
            payload       TEXT NOT NULL DEFAULT '{}',
            message_id    INTEGER,
            created_at    INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_chat ON sessions(chat_id, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
        CREATE UNIQUE INDEX IF NOT EXISTS ux_one_running_per_chat
            ON sessions(chat_id) WHERE status='running';

        CREATE TABLE IF NOT EXISTS chat_state (
            chat_id        INTEGER PRIMARY KEY,
            active_session TEXT,
            settings       TEXT NOT NULL DEFAULT '{}',
            updated_at     INTEGER NOT NULL,
            FOREIGN KEY (active_session) REFERENCES sessions(id) ON DELETE SET NULL
        );
        ''')
        conn.commit()
        _conn = conn
        _db_path = db_path
        log.info('session_store initialized: %s', db_path)
        return conn


def _get_conn():
    if _conn is None:
        init_db()
    return _conn


def _row_to_dict(row):
    if row is None:
        return None
    return {
        'id': row[0],
        'chat_id': row[1],
        'mode': row[2],
        'status': row[3],
        'payload': json.loads(row[4]) if row[4] else {},
        'message_id': row[5],
        'created_at': row[6],
        'updated_at': row[7],
    }


def _cache_get(sid):
    with _cache_lock:
        return _cache.get(sid)


def _cache_set(sid, data):
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            # evict oldest (simple: pop first key)
            try:
                _cache.pop(next(iter(_cache)))
            except StopIteration:
                pass
        _cache[sid] = data


def _cache_invalidate(sid):
    with _cache_lock:
        _cache.pop(sid, None)


def new_session_id():
    return uuid.uuid4().hex[:8]


def create_session(chat_id, mode, payload=None, message_id=None, status='awaiting_input'):
    """Buat session baru. Raise sqlite3.IntegrityError jika sudah ada running untuk chat (partial unique index)."""
    sid = new_session_id()
    now = _now()
    payload = payload or {}
    conn = _get_conn()
    with _lock:
        conn.execute(
            '''INSERT INTO sessions (id, chat_id, mode, status, payload, message_id, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?)''',
            (sid, chat_id, mode, status, json.dumps(payload), message_id, now, now))
        conn.commit()
    data = {'id': sid, 'chat_id': chat_id, 'mode': mode, 'status': status,
            'payload': payload, 'message_id': message_id, 'created_at': now, 'updated_at': now}
    _cache_set(sid, data)
    return sid


def get_session(sid):
    if not sid:
        return None
    cached = _cache_get(sid)
    if cached is not None:
        return cached
    conn = _get_conn()
    with _lock:
        row = conn.execute(
            'SELECT id, chat_id, mode, status, payload, message_id, created_at, updated_at FROM sessions WHERE id=?',
            (sid,)).fetchone()
    data = _row_to_dict(row)
    if data is not None:
        _cache_set(sid, data)
    return data


def update_session(sid, status=None, payload=None, message_id=None):
    """Partial update. payload: jika dict, merge ke payload existing; jika None, tidak ubah."""
    data = get_session(sid)
    if data is None:
        return False
    new_status = status if status is not None else data['status']
    new_payload = data['payload']
    if payload is not None:
        if isinstance(payload, dict):
            new_payload = {**new_payload, **payload}
        else:
            new_payload = payload
    new_message_id = message_id if message_id is not None else data['message_id']
    now = _now()
    conn = _get_conn()
    with _lock:
        conn.execute(
            '''UPDATE sessions SET status=?, payload=?, message_id=?, updated_at=? WHERE id=?''',
            (new_status, json.dumps(new_payload), new_message_id, now, sid))
        conn.commit()
    data.update({'status': new_status, 'payload': new_payload, 'message_id': new_message_id, 'updated_at': now})
    _cache_set(sid, data)
    return True


def get_active_session(chat_id):
    conn = _get_conn()
    with _lock:
        row = conn.execute(
            '''SELECT s.id, s.chat_id, s.mode, s.status, s.payload, s.message_id, s.created_at, s.updated_at
               FROM chat_state c LEFT JOIN sessions s ON s.id = c.active_session
               WHERE c.chat_id=?''', (chat_id,)).fetchone()
    # row from LEFT JOIN may be None columns if no active_session
    if row is None or row[0] is None:
        return None
    data = _row_to_dict(row)
    if data is not None:
        _cache_set(data['id'], data)
    return data


def set_active_session(chat_id, sid):
    now = _now()
    conn = _get_conn()
    with _lock:
        conn.execute(
            '''INSERT INTO chat_state (chat_id, active_session, settings, updated_at)
               VALUES (?,?,?,?)
               ON CONFLICT(chat_id) DO UPDATE SET active_session=excluded.active_session, updated_at=excluded.updated_at''',
            (chat_id, sid, '{}', now))
        conn.commit()
    if sid:
        _cache_invalidate(sid)  # force refresh next read


def clear_active_session(chat_id):
    set_active_session(chat_id, None)


def get_chat_settings(chat_id):
    conn = _get_conn()
    with _lock:
        row = conn.execute('SELECT settings FROM chat_state WHERE chat_id=?', (chat_id,)).fetchone()
    if not row or not row[0]:
        return {}
    try:
        return json.loads(row[0])
    except Exception:
        return {}


def set_chat_settings(chat_id, settings):
    now = _now()
    conn = _get_conn()
    with _lock:
        conn.execute(
            '''INSERT INTO chat_state (chat_id, active_session, settings, updated_at)
               VALUES (?,?,?,?)
               ON CONFLICT(chat_id) DO UPDATE SET settings=excluded.settings, updated_at=excluded.updated_at''',
            (chat_id, None, json.dumps(settings or {}), now))
        conn.commit()


def list_sessions(chat_id, limit=50):
    conn = _get_conn()
    with _lock:
        rows = conn.execute(
            '''SELECT id, chat_id, mode, status, payload, message_id, created_at, updated_at
               FROM sessions WHERE chat_id=? ORDER BY updated_at DESC LIMIT ?''',
            (chat_id, limit)).fetchall()
    return [_row_to_dict(r) for r in rows]


def prune(retention_days=7, keep_per_chat=50):
    """Hapus session lama (done/cancelled/error) > retention_days, sisakan keep_per_chat terbaru per chat."""
    cutoff = _now() - retention_days * 86400
    conn = _get_conn()
    with _lock:
        # hapus yang expired dan bukan running
        conn.execute(
            '''DELETE FROM sessions
               WHERE status IN ('done','cancelled','error')
                 AND updated_at < ?''', (cutoff,))
        # per chat: sisakan keep_per_chat terbaru
        chats = [r[0] for r in conn.execute('SELECT DISTINCT chat_id FROM sessions').fetchall()]
        for c in chats:
            ids = [r[0] for r in conn.execute(
                'SELECT id FROM sessions WHERE chat_id=? ORDER BY updated_at DESC', (c,)).fetchall()]
            for sid in ids[keep_per_chat:]:
                conn.execute('DELETE FROM sessions WHERE id=?', (sid,))
        conn.commit()
    # invalidate cache entries that were removed (best-effort)
    with _cache_lock:
        # drop cache keys not in db anymore (cheap: clear all)
        _cache.clear()


def close():
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None


# Self-test (opsional): jalankan `python3 -m bot.session_store` untuk sanity check.
if __name__ == '__main__':
    import tempfile
    p = os.path.join(tempfile.gettempdir(), 'session_store_selftest.db')
    try:
        os.remove(p)
    except FileNotFoundError:
        pass
    init_db(p)
    sid = create_session(123, 'subfind', payload={'domain': 'example.com'}, status='running')
    print('created', sid)
    assert get_session(sid)['payload']['domain'] == 'example.com'
    update_session(sid, status='done', payload={'scan_page': 2})
    s = get_session(sid)
    print('status', s['status'], 'payload', s['payload'])
    assert s['status'] == 'done' and s['payload']['scan_page'] == 2 and s['payload']['domain'] == 'example.com'
    set_active_session(123, sid)
    assert get_active_session(123)['id'] == sid
    clear_active_session(123)
    assert get_active_session(123) is None
    set_chat_settings(123, {'lang': 'id'})
    assert get_chat_settings(123) == {'lang': 'id'}
    prune(retention_days=0, keep_per_chat=0)
    print('prune ok')
    close()
    print('SELFTEST OK')
