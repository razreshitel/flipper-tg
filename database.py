import aiosqlite
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent / "data" / "messages.db"


async def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT,
                type TEXT DEFAULT 'private',
                message_count INTEGER DEFAULT 0,
                last_message_at TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER,
                chat_id INTEGER NOT NULL,
                from_id INTEGER,
                from_name TEXT,
                text TEXT,
                date TEXT NOT NULL,
                message_type TEXT DEFAULT 'text',
                FOREIGN KEY (chat_id) REFERENCES chats(id)
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, date DESC)"
        )
        await db.commit()


async def save_message(
    chat_id, chat_name, chat_username, chat_type,
    from_id, from_name, text, date, message_type="text", telegram_id=None,
):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO chats (id, name, username, type, message_count, last_message_at)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                message_count=message_count + 1,
                last_message_at=excluded.last_message_at
            """,
            (chat_id, chat_name, chat_username, chat_type, date.isoformat()),
        )
        await db.execute(
            """
            INSERT INTO messages (telegram_id, chat_id, from_id, from_name, text, date, message_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (telegram_id, chat_id, from_id, from_name, text, date.isoformat(), message_type),
        )
        await db.commit()


async def save_sent_message(chat_id: int, text: str, telegram_id: int | None = None):
    """Save a message sent by the bot (from Flipper or web UI) to the DB."""
    now = datetime.now(timezone.utc)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE chats SET message_count = message_count + 1, last_message_at = ? WHERE id = ?",
            (now.isoformat(), chat_id),
        )
        await db.execute(
            """
            INSERT INTO messages (telegram_id, chat_id, from_id, from_name, text, date, message_type)
            VALUES (?, ?, NULL, 'Me', ?, ?, 'text')
            """,
            (telegram_id, chat_id, text, now.isoformat()),
        )
        await db.commit()


async def delete_message(message_id: int) -> bool:
    """Delete a message by its DB id; decrements the parent chat's message_count."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT chat_id FROM messages WHERE id = ?", (message_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return False
        chat_id = row[0]
        await db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        await db.execute(
            "UPDATE chats SET message_count = MAX(0, message_count - 1) WHERE id = ?",
            (chat_id,),
        )
        await db.commit()
    return True


async def ensure_chat(chat_id: int, name: str, username: str | None, chat_type: str):
    """Insert a chat row if it doesn't already exist."""
    now = datetime.now(timezone.utc)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO chats (id, name, username, type, message_count, last_message_at)
            VALUES (?, ?, ?, ?, 0, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (chat_id, name, username, chat_type, now.isoformat()),
        )
        await db.commit()


async def get_chats(limit=50):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM chats ORDER BY last_message_at DESC LIMIT ?", (limit,)
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def get_messages(chat_id, page=0, per_page=30, newest_first=False):
    offset = page * per_page
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM messages WHERE chat_id = ? ORDER BY date DESC LIMIT ? OFFSET ?",
            (chat_id, per_page, offset),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return rows if newest_first else list(reversed(rows))


async def get_chat(chat_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM chats WHERE id = ?", (chat_id,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def get_message_count(chat_id):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM messages WHERE chat_id = ?", (chat_id,)
        ) as cur:
            row = await cur.fetchone()
    return row[0] if row else 0
