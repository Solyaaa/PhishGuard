import logging
import asyncio
import aiohttp
import hashlib
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.utils.keyboard import ReplyKeyboardBuilder, InlineKeyboardBuilder
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

API_TOKEN = '8591632480:AAES8D7UWIaI14ho4mgsQGiZPcF5HCqHTmg'
API_URL_SCAN = "http://127.0.0.1:5001/api/scan"
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

logging.basicConfig(level=logging.INFO)
bot = Bot(token=API_TOKEN)
dp = Dispatcher()


class UserStates(StatesGroup):
    choosing_mode = State()
    waiting_for_url = State()
    waiting_for_password = State()


@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    await state.clear()
    builder = ReplyKeyboardBuilder()
    builder.button(text="🔗 1. Перевірити лінк")
    builder.button(text="🔑 2. Перевірити пароль")
    builder.adjust(2)

    await message.answer(
        "🛡️ **Вітаю у TrustyLink!**\n\nОберіть режим перевірки:",
        reply_markup=builder.as_markup(resize_keyboard=True),
        parse_mode=ParseMode.MARKDOWN
    )
    await state.set_state(UserStates.choosing_mode)


@dp.message(UserStates.choosing_mode)
async def process_mode(message: types.Message, state: FSMContext):
    if "1. Перевірити лінк" in message.text:
        await state.set_state(UserStates.waiting_for_url)
        await message.answer("Надішліть URL для аналізу:", reply_markup=types.ReplyKeyboardRemove())
    elif "2. Перевірити пароль" in message.text:
        await state.set_state(UserStates.waiting_for_password)
        await message.answer("Надішліть пароль (його буде видалено з чату):", reply_markup=types.ReplyKeyboardRemove())


@dp.message(UserStates.waiting_for_url)
async def handle_url(message: types.Message, state: FSMContext):
    url = message.text.strip()
    await analyze_url(message, url)
    await state.set_state(UserStates.choosing_mode)
    await show_menu(message)


@dp.message(UserStates.waiting_for_password)
async def handle_password(message: types.Message, state: FSMContext):
    password = message.text.strip()
    try:
        await bot.delete_message(message.chat.id, message.message_id)
    except:
        pass
    await analyze_password(message, password)
    await state.set_state(UserStates.choosing_mode)
    await show_menu(message)


async def show_menu(message: types.Message):
    builder = ReplyKeyboardBuilder()
    builder.button(text="🔗 1. Перевірити лінк")
    builder.button(text="🔑 2. Перевірити пароль")
    builder.adjust(2)
    await message.answer("Що перевіримо наступним?", reply_markup=builder.as_markup(resize_keyboard=True))


# --- ПЕРЕВІРКА ПАРОЛЯ ---
async def check_password_leak(password: str):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    async with aiohttp.ClientSession() as session:
        async with session.get(HIBP_API_URL + prefix) as response:
            if response.status == 200:
                text = await response.text()
                for line in text.splitlines():
                    res_suffix, count = line.split(':')
                    if res_suffix == suffix:
                        return int(count)
    return 0


async def analyze_password(message: types.Message, password: str):
    loading_msg = await message.answer("🔑 *Перевіряю...*")
    count = await check_password_leak(password)
    if count > 0:
        await loading_msg.edit_text(f"🚫 **Знайдено витік!**\n\nПароль знайдено `{count}` разів.")
    else:
        await loading_msg.edit_text("✅ **Пароль чистий.**")



async def analyze_url(message: types.Message, url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    loading_msg = await message.answer("🔍 *Аналізую посилання...*")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(API_URL_SCAN, json={"url": url}, timeout=20) as response:
                if response.status == 200:
                    data = await response.json()
                    status = data.get('status', 'safe')
                    score = data.get('final_score', 0)

                    icon = "✅" if status == "safe" else "⚠️" if status == "warning" else "🚫"
                    verdict = "БЕЗПЕЧНО" if status == "safe" else "ПІДОЗРІЛО" if status == "warning" else "ФІШИНГ"

                    res_text = (
                        f"{icon} **Результат аналізу**\n"
                        f"---------------------------\n"
                        f" **URL:** `{data['url']}`\n"
                        f" **Безпека:** `{score}%`\n"
                        f" **Вердикт:** `{verdict}`\n\n"
                        f"**Деталі перевірок:**\n"
                    )
                    for check in data.get('checks', []):
                        r_icon = "🟢" if check['result'] == 'pass' else "🟡" if check['result'] == 'warning' else "🔴"
                        res_text += f"{r_icon} {check['description']}\n"

                    await loading_msg.edit_text(res_text, parse_mode=ParseMode.MARKDOWN)
                else:
                    await loading_msg.edit_text("❌ Помилка API сервера.")
    except Exception as e:
        await loading_msg.edit_text("❗ Не вдалося підключитися до сервера Flask.")


async def main():
    await dp.start_polling(bot)


if __name__ == '__main__':
    asyncio.run(main())