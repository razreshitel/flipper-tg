import os
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from database import save_message

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
SOCKS_PROXY = os.getenv("SOCKS_PROXY", "")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg:
        return

    chat = update.effective_chat
    user = update.effective_user

    chat_name = chat.title or getattr(chat, "full_name", None) or chat.username or str(chat.id)
    from_name = user.full_name if user else "Unknown"

    text = msg.text or msg.caption or ""
    message_type = "text"

    if msg.photo:
        message_type = "photo"
        text = text or "[Photo]"
    elif msg.video:
        message_type = "video"
        text = text or "[Video]"
    elif msg.voice:
        message_type = "voice"
        text = "[Voice message]"
    elif msg.audio:
        message_type = "audio"
        text = text or "[Audio]"
    elif msg.document:
        message_type = "document"
        text = text or f"[File: {msg.document.file_name or 'unknown'}]"
    elif msg.sticker:
        message_type = "sticker"
        text = f"[Sticker {msg.sticker.emoji or ''}]"
    elif msg.location:
        message_type = "location"
        text = f"[Location {msg.location.latitude:.4f}, {msg.location.longitude:.4f}]"
    elif msg.contact:
        message_type = "contact"
        text = f"[Contact: {msg.contact.first_name}]"

    await save_message(
        chat_id=chat.id,
        chat_name=chat_name,
        chat_username=getattr(chat, "username", None),
        chat_type=chat.type,
        from_id=user.id if user else None,
        from_name=from_name,
        text=text,
        date=msg.date,
        message_type=message_type,
        telegram_id=msg.message_id,
    )


def setup_bot():
    builder = Application.builder().token(BOT_TOKEN)
    if SOCKS_PROXY:
        builder = builder.proxy(SOCKS_PROXY).get_updates_proxy(SOCKS_PROXY)
    return builder.build()


def setup_bot_with_handlers():
    bot_app = setup_bot()
    bot_app.add_handler(MessageHandler(filters.ALL, handle_message))
    return bot_app
