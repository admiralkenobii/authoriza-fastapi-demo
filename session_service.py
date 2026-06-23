from fastapi import Request

from auth_storage import load_auth_data
from token_service import check_token


# восстановление сессии
async def restore_session(request: Request) -> None:
    if request.session.get("token"):  # если активные куки уже есть
        print("Session already exists")
        return  # то делать ничего не нужно

    auth_data = load_auth_data()
    if not auth_data:
        return

    print("Restoring session from JSON")
    # иначе - восстанавливаем данные из json
    request.session["token"] = auth_data["token"]
    request.session["user"] = auth_data["user"]
    request.session["login_time"] = auth_data["login_time"]
    request.session["access_token_expires_at"] = auth_data["access_token_expires_at"]
    request.session["userinfo_received_at"] = auth_data.get("userinfo_received_at")
    request.session["refresh_token_expires_at"] = auth_data.get("refresh_token_expires_at")
    request.session["last_refresh_time"] = auth_data.get("last_refresh_time")

    # сразу проверяем срок жизни access_token
    await check_token(request)
