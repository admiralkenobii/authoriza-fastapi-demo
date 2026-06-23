import json
import os
from pathlib import Path
from typing import Any, Optional

AUTH_FILE = Path(os.getenv("AUTH_FILE", "auth_data.json"))


# сохранение данных авторизации в json-файл
def save_auth_data(
    token: dict[str, Any],
    user: Optional[dict[str, Any]],
    login_time: str,
    access_token_expires_at: str,
    refresh_token_expires_at: Optional[str],
    userinfo_received_at: Optional[str],
    last_refresh_time: Optional[str] = None,
) -> None:
    data = {
        "token": token,
        "user": user,
        "login_time": login_time,
        "access_token_expires_at": access_token_expires_at,
        "refresh_token_expires_at": refresh_token_expires_at,
        "userinfo_received_at": userinfo_received_at,
        "last_refresh_time": last_refresh_time,
    }

    with AUTH_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


# загрузка данных авторизации
def load_auth_data() -> Optional[dict[str, Any]]:
    if not AUTH_FILE.exists():
        return None

    with AUTH_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


# удаление json-файла
def clear_auth_data() -> None:
    if AUTH_FILE.exists():
        AUTH_FILE.unlink()
