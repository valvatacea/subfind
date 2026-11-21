#!/usr/bin/env python3
# Setup profil bot Surfinder via pyTelegramBotAPI
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

# ===================== PROFILE PHOTO =====================
print("\n⚠️  Foto profil TIDAK bisa diubah via Telegram Bot API.")
print("   Gunakan @BotFather → /setuserpic → pilih bot → kirim foto.")
print("   Rekomendasi: ikon globe 🌐 atau shield 🛡️, PNG 640×640.")

print("\n✅ Setup selesai. Coba /start di Telegram.")
