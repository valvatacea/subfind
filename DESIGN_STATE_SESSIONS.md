# Desain: State Session-Per-Scan + Persist SQLite (Subfind Bot)

## 1. Tujuan & Non-Tujuan

- **Tujuan:** menghilangkan race "state berpindah saat scan jalan" dan membuat state survive restart.
- **Non-tujuan:** tidak mengubah UX scan (progress, pagination, filter tetap). Tidak migrasi data historis output JSON (tetap file).

## 2. Prinsip

- Satu **session** = satu flow scan (subfind/cdnscan/sniscan/d2ip) dengan lifecycle sendiri.
- State chat hanya menyimpan `active_session_id` (nullable) untuk default rendering.
- Semua tombol progress membawa `session_id` di `callback_data` (8 char hex).
- In-memory cache tetap dipakai untuk hot path; DB = source of truth + recovery.

## 3. Skema SQLite (file: `bot/state.db`, WAL mode)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,          -- 8 hex (uuid4[:8])
    chat_id       INTEGER NOT NULL,
    mode          TEXT NOT NULL,             -- subfind|cdnscan|sniscan|d2ip
    status        TEXT NOT NULL,             -- idle|awaiting_input|running|done|cancelled|error
    payload       TEXT NOT NULL DEFAULT '{}',-- JSON: domain, targets, scan_page, filter_*, dll
    message_id    INTEGER,                   -- progress/result message id
    created_at    INTEGER NOT NULL,          -- unix ts
    updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_chat ON sessions(chat_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

CREATE TABLE IF NOT EXISTS chat_state (
    chat_id        INTEGER PRIMARY KEY,
    active_session TEXT,                     -- FK sessions.id (nullable)
    settings       TEXT NOT NULL DEFAULT '{}',-- lang, currency, autocancel (terpisah!)
    updated_at     INTEGER NOT NULL,
    FOREIGN KEY (active_session) REFERENCES sessions(id) ON DELETE SET NULL
);
```

**Catatan:** settings dipisah dari flow state → `clear_state` tidak lagi menghapus settings.

## 4. Mapping State Keys Lama → Baru

| Key lama | Lokasi baru |
|---|---|
| `mode`, `awaiting`, `prev_menu` | `sessions.status` + `payload.prev_menu` |
| `cdn_targets`, `cdn_selected`, `cdn_ranges`, `cdn_provider`, `cdn_limit`, `cdn_range_page` | `payload.*` (cdnscan) |
| `scan_page`, `scan_back_target`, `scan_filters`, `filter_mode`, `filter_field` | `payload.*` (semua mode) |
| `*_history_page` | `chat_state`? atau payload (tetap per chat, bukan per session) → simpan di `chat_state.payload` ringan |
| `scanning` | `sessions.status == 'running'` |
| settings (lang/currency/autocancel) | `chat_state.settings` |

## 5. Lifecycle Session

```
IDLE (chat_state.active_session=NULL)
  -> start flow: create session status=awaiting_input, set active_session
  -> input diterima: status=running
  -> scan selesai: status=done, active_session=NULL (atau tetap untuk view)
  -> cancel: status=cancelled
  -> error: status=error
  -> navigasi menu utama: active_session=NULL (session tetap di DB, status done/cancelled)
```

**Guard:** handler yang butuh session aktif cek `sessions.status`; kalau tidak match → ignore atau balik ke menu.

## 6. Concurrency & Locking

- SQLite WAL + `busy_timeout=5000`.
- Semua write session dibungkus transaction.
- In-memory LRU cache (max 64 session) untuk hot path; invalidate on write.
- Satu scan aktif per chat: enforce via partial unique index:
  ```sql
  CREATE UNIQUE INDEX IF NOT EXISTS ux_one_running_per_chat
    ON sessions(chat_id) WHERE status='running';
  ```

## 7. Langkah Migrasi (Bertahap, Reversible)

### Fase 0 — Persiapan (tanpa ubah perilaku)
1. Tambah modul `bot/session_store.py` (SQLite + cache + CRUD).
2. Tambah tabel `sessions`, `chat_state` saat startup (idempotent).
3. Tulis unit-ish sanity: buat session, update payload, read back.

### Fase 1 — Dual-write (state lama tetap primary)
1. Setiap `set_state(chat_id, ...)` juga `upsert session` (jika ada active_session) atau buat session baru.
2. `get_state` tetap baca dict in-memory; DB hanya mirror.
3. Verifikasi: DB payload == dict state (log mismatch, jangan crash).

### Fase 2 — Switch read ke session (primary DB)
1. Handler baca via `get_session(chat_id)` → payload; fallback ke dict lama jika None.
2. `callback_data` mulai membawa `sid` (session_id) untuk tombol progress.
3. Scan thread pegang `session_id` dari awal; tidak baca `user_state` global.
4. `clear_state` diganti:
   - `clear_flow(chat_id)` → set active_session=NULL, session.status=done/cancelled.
   - settings tetap di `chat_state.settings`.

### Fase 3 — Hapus state lama
1. Hapus `user_state` dict global dan `set_state`/`get_state`/`clear_state` lama.
2. Ganti semua call site (90 referensi) ke session API.
3. Pruning: job harian hapus session status done/cancelled/error older than 7 hari (keep last 50 per chat).

### Fase 4 — Hardening
1. Validasi payload schema per mode (required keys).
2. Migration script: jika DB lama (pre-session) ada, import `chat_state` dari file state lama (jika ada).
3. Backup DB sebelum upgrade (copy file).

## 8. Touchpoints Kode (file/fungsi)

- `bot/main.py`: semua `set_state`/`get_state`/`clear_state` (90 refs), `cmd_start`, `cb_handler` (router), `run_subfind`, `run_cdnscan_target_batch`, `run_sniscan`, `show_scan_page`, history pages.
- Baru: `bot/session_store.py` (CRUD, cache, pruning).
- `bot/__init__.py` tidak berubah.
- Tambah `bot/state.db*` ke `.gitignore`.

## 9. Rollback Plan

- Fase 1-2: reversible (dict lama masih primary/mirror).
- Fase 3+: butuh restore dari backup git (sebelum Fase 3 commit) + restore `bot/state.db` backup.
- Selalu commit per fase; jangan gabung.

## 10. Risiko & Mitigasi

| Risiko | Mitigasi |
|---|---|
| callback_data > 64 byte dengan sid | gunakan sid 8 char; payload detail di DB |
| SQLite lock under load | WAL + busy_timeout + retry; cache hot path |
| Migrasi partial crash | transaction per session; idempotent upsert |
| Perilaku berubah (regression) | Fase 1-2 dual-write + log mismatch sebelum switch |
| Scan thread baca state lama | Fase 2: thread pegang session_id, tidak baca global |

## 11. Estimasi Effort

- Fase 0-1: 1-2 hari.
- Fase 2: 2-3 hari (touchpoints banyak).
- Fase 3-4: 1-2 hari.
- Total: ~1 minggu kerja, dengan testing manual tiap fase.

## 12. Keputusan yang Butuh Konfirmasi User

1. Nama file DB: `output/state.db` (atau `bot/state.db`)? 
2. Retensi session: 7 hari / 50 per chat — OK?
3. Apakah mau mulai Fase 0 (tambah modul saja, tanpa ubah perilaku) sekarang? Butuh konfirmasi sebelum eksekusi.
```

Let me write this file.<|end|><|start|> startX <|constrain|>xml<|message|><rfl:parameter name="content">
# Desain: State Session-Per-Scan + Persist SQLite (Subfind Bot)

## 1. Tujuan & Non-Tujuan

- **Tujuan:** menghilangkan race "state berpindah saat scan jalan" dan membuat state survive restart.
- **Non-tujuan:** tidak mengubah UX scan (progress, pagination, filter tetap). Tidak migrasi data historis output JSON (tetap file).

## 2. Prinsip

- Satu **session** = satu flow scan (subfind/cdnscan/sniscan/d2ip) dengan lifecycle sendiri.
- State chat hanya menyimpan `active_session_id` (nullable) untuk default rendering.
- Semua tombol progress membawa `session_id` di `callback_data` (8 char hex).
- In-memory cache tetap dipakai untuk hot path; DB = source of truth + recovery.

## 3. Skema SQLite (file: `bot/state.db`, WAL mode)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,          -- 8 hex (uuid4[:8])
    chat_id       INTEGER NOT NULL,
    mode          TEXT NOT NULL,             -- subfind|cdnscan|sniscan|d2ip
    status        TEXT NOT NULL,             -- idle|awaiting_input|running|done|cancelled|error
    payload       TEXT NOT NULL DEFAULT '{}',-- JSON: domain, targets, scan_page, filter_*, dll
    message_id    INTEGER,                   -- progress/result message id
    created_at    INTEGER NOT NULL,          -- unix ts
    updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_chat ON sessions(chat_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

CREATE TABLE IF NOT EXISTS chat_state (
    chat_id        INTEGER PRIMARY KEY,
    active_session TEXT,                     -- FK sessions.id (nullable)
    settings       TEXT NOT NULL DEFAULT '{}',-- lang, currency, autocancel (terpisah!)
    updated_at     INTEGER NOT NULL,
    FOREIGN KEY (active_session) REFERENCES sessions(id) ON DELETE SET NULL
);
```

**Catatan:** settings dipisah dari flow state → `clear_state` tidak lagi menghapus settings.

## 4. Mapping State Keys Lama → Baru

| Key lama | Lokasi baru |
|---|---|
| `mode`, `awaiting`, `prev_menu` | `sessions.status` + `payload.prev_menu` |
| `cdn_targets`, `cdn_selected`, `cdn_ranges`, `cdn_provider`, `cdn_limit`, `cdn_range_page` | `payload.*` (cdnscan) |
| `scan_page`, `scan_back_target`, `scan_filters`, `filter_mode`, `filter_field` | `payload.*` (semua mode) |
| `*_history_page` | `chat_state`? atau payload (tetap per chat, bukan per session) → simpan di `chat_state.payload` ringan |
| `scanning` | `sessions.status == 'running'` |
| settings (lang/currency/autocancel) | `chat_state.settings` |

## 5. Lifecycle Session

```
IDLE (chat_state.active_session=NULL)
  -> start flow: create session status=awaiting_input, set active_session
  -> input diterima: status=running
  -> scan selesai: status=done, active_session=NULL (atau tetap untuk view)
  -> cancel: status=cancelled
  -> error: status=error
  -> navigasi menu utama: active_session=NULL (session tetap di DB, status done/cancelled)
```

**Guard:** handler yang butuh session aktif cek `sessions.status`; kalau tidak match → ignore atau balik ke menu.

## 6. Concurrency & Locking

- SQLite WAL + `busy_timeout=5000`.
- Semua write session dibungkus transaction.
- In-memory LRU cache (max 64 session) untuk hot path; invalidate on write.
- Satu scan aktif per chat: enforce via partial unique index:
  ```sql
  CREATE UNIQUE INDEX IF NOT EXISTS ux_one_running_per_chat
    ON sessions(chat_id) WHERE status='running';
  ```

## 7. Langkah Migrasi (Bertahap, Reversible)

### Fase 0 — Persiapan (tanpa ubah perilaku)
1. Tambah modul `bot/session_store.py` (SQLite + cache + CRUD).
2. Tambah tabel `sessions`, `chat_state` saat startup (idempotent).
3. Tulis unit-ish sanity: buat session, update payload, read back.

### Fase 1 — Dual-write (state lama tetap primary)
1. Setiap `set_state(chat_id, ...)` juga `upsert session` (jika ada active_session) atau buat session baru.
2. `get_state` tetap baca dict in-memory; DB hanya mirror.
3. Verifikasi: DB payload == dict state (log mismatch, jangan crash).

### Fase 2 — Switch read ke session (primary DB)
1. Handler baca via `get_session(chat_id)` → payload; fallback ke dict lama jika None.
2. `callback_data` mulai membawa `sid` (session_id) untuk tombol progress.
3. Scan thread pegang `session_id` dari awal; tidak baca `user_state` global.
4. `clear_state` diganti:
   - `clear_flow(chat_id)` → set active_session=NULL, session.status=done/cancelled.
   - settings tetap di `chat_state.settings`.

### Fase 3 — Hapus state lama
1. Hapus `user_state` dict global dan `set_state`/`get_state`/`clear_state` lama.
2. Ganti semua call site (90 referensi) ke session API.
3. Pruning: job harian hapus session status done/cancelled/error older than 7 hari (keep last 50 per chat).

### Fase 4 — Hardening
1. Validasi payload schema per mode (required keys).
2. Migration script: jika DB lama (pre-session) ada, import `chat_state` dari file state lama (jika ada).
3. Backup DB sebelum upgrade (copy file).

## 8. Touchpoints Kode (file/fungsi)

- `bot/main.py`: semua `set_state`/`get_state`/`clear_state` (90 refs), `cmd_start`, `cb_handler` (router), `run_subfind`, `run_cdnscan_target_batch`, `run_sniscan`, `show_scan_page`, history pages.
- Baru: `bot/session_store.py` (CRUD, cache, pruning).
- `bot/__init__.py` tidak berubah.
- Tambah `bot/state.db*` ke `.gitignore`.

## 9. Rollback Plan

- Fase 1-2: reversible (dict lama masih primary/mirror).
- Fase 3+: butuh restore dari backup git (sebelum Fase 3 commit) + restore `bot/state.db` backup.
- Selalu commit per fase; jangan gabung.

## 10. Risiko & Mitigasi

| Risiko | Mitigasi |
|---|---|
| callback_data > 64 byte dengan sid | gunakan sid 8 char; payload detail di DB |
| SQLite lock under load | WAL + busy_timeout + retry; cache hot path |
| Migrasi partial crash | transaction per session; idempotent upsert |
| Perilaku berubah (regression) | Fase 1-2 dual-write + log mismatch sebelum switch |
| Scan thread baca state lama | Fase 2: thread pegang session_id, tidak baca global |

## 11. Estimasi Effort

- Fase 0-1: 1-2 hari.
- Fase 2: 2-3 hari (touchpoints banyak).
- Fase 3-4: 1-2 hari.
- Total: ~1 minggu kerja, dengan testing manual tiap fase.

## 12. Keputusan yang Butuh Konfirmasi User

1. Nama file DB: `output/state.db` (atau `bot/state.db`)?
2. Retensi session: 7 hari / 50 per chat — OK?
3. Apakah mau mulai Fase 0 (tambah modul saja, tanpa ubah perilaku) sekarang? Butuh konfirmasi sebelum eksekusi.
