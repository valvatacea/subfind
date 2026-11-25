#!/usr/bin/env python3
# Setup profil bot Surfinder (gabungan): commands, description, dan foto profil
# Jalankan sekali: python3 bot/setup_profile.py
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

import telebot

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    print("BOT_TOKEN belum di-set di bot/.env")
    sys.exit(1)

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

# ===================== SET COMMANDS =====================
commands = [
    telebot.types.BotCommand("start", "Mulai bot dan lihat menu"),
    telebot.types.BotCommand("menu", "Tampilkan menu utama"),
    telebot.types.BotCommand("help", "Bantuan penggunaan"),
]
try:
    bot.set_my_commands(commands)
    print("✅ Commands di-set")
except Exception as e:
    print(f"❌ Gagal set commands: {e}")

# ===================== SET DESCRIPTION (panjang) =====================
description = (
    "Surfinder — Bot pencarian subdomain, resolve domain ke IP, dan deteksi CDN.\n\n"
    "Pilih menu D2IP, SubFind, atau CDNScan. Hanya butuh input domain atau IP, "
    "tidak ada form ribet. Semua hasil bisa di-navigasi dengan paginasi."
)
try:
    bot.set_my_description(description)
    print("✅ Description di-set")
except Exception as e:
    print(f"❌ Gagal set description: {e}")

# ===================== SET ABOUT / SHORT DESCRIPTION =====================
short_desc = "Subdomain, IP, dan CDN scanner via tombol inline"
try:
    bot.set_my_short_description(short_desc)
    print("✅ About (short description) di-set")
except Exception as e:
    print(f"❌ Gagal set about: {e}")

# ===================== SET PROFIL FOTO =====================
try:
    from PIL import Image, ImageDraw
    import requests

    # Buat gambar profil dari nol (lingkaran biru + tanda perisai)
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

    img_path = '/tmp/surfinder_profile.png'
    img.save(img_path, format='PNG')
    print(f"✅ Gambar profil disimpan: {img_path}")

    # Set profil foto via raw Telegram Bot API setMyProfilePhoto
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setMyProfilePhoto"
    with open(img_path, 'rb') as f:
        resp = requests.post(
            url,
            data={'photo': '{"type":"static","photo":"attach://photo"}'},
            files={'photo': ('surfinder_profile.png', f, 'image/png')},
            timeout=30
        )
    data = resp.json()
    if data.get('ok'):
        print("✅ Profil foto bot berhasil diubah via setMyProfilePhoto")
    else:
        print(f"❌ Gagal set profil foto: {data}")

except ImportError as e:
    print(f"⚠️  Pillow atau requests tidak terpasang, lewati foto profil: {e}")
except Exception as e:
    print(f"❌ Error saat set profil foto: {e}")

print("\n✅ Setup selesai. Coba /start di Telegram.")
