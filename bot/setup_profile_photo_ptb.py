#!/usr/bin/env python3
# Set profil foto bot Surfinder via python-telegram-bot (set_my_profile_photo)
# Jalankan sekali: python3 bot/setup_profile_photo_ptb.py
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from telegram import Bot, InputProfilePhotoStatic

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    print("BOT_TOKEN belum di-set di bot/.env")
    sys.exit(1)

# Path ke foto profil — gunakan image yang sudah ada dari dokumen
PHOTO_PATH = '/root/.hermes/cache/documents/native-inputs/ef43c1c6568b13f3a31a81f9d7cb79de0918c200a4bc855e46945cb9b9c52dd0/img_9537aab2901c.jpg'
if not os.path.exists(PHOTO_PATH):
    print(f"Foto tidak ditemukan: {PHOTO_PATH}")
    sys.exit(1)

async def main():
    bot = Bot(token=BOT_TOKEN)
    try:
        with open(PHOTO_PATH, 'rb') as f:
            photo = InputProfilePhotoStatic(photo=f)
            result = await bot.set_my_profile_photo(
                photo=photo,
                read_timeout=60,
                write_timeout=60,
                connect_timeout=60,
            )
        print("SUCCESS:", result)
    except Exception as e:
        print(f"ERROR: {e}")

asyncio.run(main())
