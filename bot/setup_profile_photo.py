#!/usr/bin/env python3
# Set profil foto bot via setMyProfilePhoto (raw Telegram Bot API)
# Jalankan sekali: python3 bot/setup_profile_photo.py
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from PIL import Image, ImageDraw
import telebot

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    print("BOT_TOKEN belum di-set di bot/.env")
    sys.exit(1)

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

# ===================== BUAT GAMBAR PROFIL =====================
size = 640
img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

bg_color = (0, 137, 213, 255)
draw.ellipse([20, 20, size - 20, size - 20], fill=bg_color)

shield_color = (255, 255, 255, 240)
cx, cy = size // 2, size // 2
shield_w = 260
shield_h = 280
shield_top = cy - shield_h // 2
shield_bottom = cy + shield_h // 2
shield_left = cx - shield_w // 2
shield_right = cx + shield_w // 2

draw.pieslice([shield_left, shield_top, shield_right, shield_top + shield_h // 2], 180, 360, fill=shield_color)
draw.rectangle([shield_left, shield_top + shield_h // 4, shield_right, shield_bottom], fill=shield_color)
draw.polygon([
    (shield_left, shield_bottom - 40),
    (cx, shield_bottom),
    (shield_right, shield_bottom - 40),
], fill=shield_color)

glass_color = (0, 137, 213, 255)
glass_cx = cx + 40
glass_cy = cy + 20
glass_r = 45
draw.ellipse([glass_cx - glass_r, glass_cy - glass_r, glass_cx + glass_r, glass_cy + glass_r], outline=glass_color, width=14)
draw.line([glass_cx + glass_r * 0.7, glass_cy + glass_r * 0.7, glass_cx + glass_r * 1.15, glass_cy + glass_r * 1.15], fill=glass_color, width=14)

# Simpan ke file (bukan BytesIO agar format pasti benar)
img_path = '/tmp/surfinder_profile.png'
img.save(img_path, format='PNG')
print(f"✅ Gambar profil disimpan: {img_path}")

# ===================== SET PROFIL FOTO VIA setMyProfilePhoto =====================
url = f"https://api.telegram.org/bot{BOT_TOKEN}/setMyProfilePhoto"

try:
    with open(img_path, 'rb') as f:
        resp = requests.post(
            url,
            files={'photo': ('surfinder_profile.png', f, 'image/png')},
            timeout=30
        )
    data = resp.json()
    if data.get('ok'):
        print("✅ Profil foto bot berhasil diubah via setMyProfilePhoto")
    else:
        print(f"❌ Gagal set profil foto: {data}")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n✅ Setup profil foto selesai.")
