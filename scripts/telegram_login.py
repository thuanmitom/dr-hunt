"""One-time interactive login that prints a Telethon StringSession for HC_TELEGRAM_SESSION.

Use a dedicated research account, never a personal one. Run outside the container:
    HC_TELEGRAM_API_ID=... HC_TELEGRAM_API_HASH=... python -m scripts.telegram_login
"""

from __future__ import annotations

import os

from telethon.sessions import StringSession
from telethon.sync import TelegramClient


def main() -> None:
    api_id, api_hash = int(os.environ["HC_TELEGRAM_API_ID"]), os.environ["HC_TELEGRAM_API_HASH"]
    with TelegramClient(StringSession(), api_id, api_hash) as client:
        print("HC_TELEGRAM_SESSION=" + client.session.save())


if __name__ == "__main__":
    main()
