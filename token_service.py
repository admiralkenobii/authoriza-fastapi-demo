from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Request

from auth_storage import clear_auth_data, save_auth_data
from oauth_client import oauth


def get_refresh_expires_at(token: dict) -> str | None:
    if "refresh_expires_in" in token:
        return (datetime.now(timezone.utc) + timedelta(seconds=token["refresh_expires_in"])).isoformat()

    # декодируем refresh_token как JWT
    rt = token.get("refresh_token")
    payload = decode_token_payload(rt)
    if payload and "exp" in payload:
        return datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat()

    # иначе
    return None


# декодировка JWT без проверки подписи
def decode_token_payload(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None

    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None


# функция обновления токенов
async def refresh_tokens(request: Request) -> bool:
    token = request.session.get("token")

    if not token:
        return False

    refresh_token = token.get("refresh_token")

    if not refresh_token:
        return False

    metadata = await oauth.authoriza.load_server_metadata()
    token_endpoint = metadata.get("token_endpoint")
    userinfo_endpoint = metadata.get("userinfo_endpoint")

    async with oauth.authoriza._get_oauth_client(**metadata) as client:
        new_token = await client.refresh_token(
            url=token_endpoint,
            refresh_token=refresh_token,
        )

    request.session["token"] = new_token
    request.session["access_token_expires_at"] = (
        datetime.now(timezone.utc) + timedelta(seconds=new_token["expires_in"])
    ).isoformat()

    if "refresh_expires_in" in new_token:
        request.session["refresh_token_expires_at"] = (
            datetime.now(timezone.utc) + timedelta(seconds=new_token["refresh_expires_in"])
        ).isoformat()
    else:
        request.session["refresh_token_expires_at"] = get_refresh_expires_at(new_token)

    request.session["last_refresh_time"] = datetime.now().isoformat()

    # обновление UserInfo
    if userinfo_endpoint:
        try:
            headers = {
                "Authorization": f"Bearer {new_token['access_token']}",
            }

            async with oauth.authoriza._get_oauth_client(**metadata) as client2:
                resp = await client2.get(userinfo_endpoint, headers=headers)

            if resp.status_code == 200:
                request.session["user"] = resp.json()
                request.session["userinfo_received_at"] = datetime.now().isoformat()

        except Exception as e:
            print(f"[AUTO REFRESH] UserInfo error: {e}")

    # сохранение новых токенов
    # так как вызов внутри функции обновления, токены всегда свежие
    save_auth_data(
        request.session["token"],
        request.session["user"],
        request.session["login_time"],
        request.session["access_token_expires_at"],
        request.session.get("refresh_token_expires_at"),  # для предотвращения KeyError
        request.session.get("userinfo_received_at"),
        request.session.get("last_refresh_time"),
    )

    return True


async def check_token(request: Request) -> None:
    # проверка refresh_token. если истёк - выходим из аккаунта
    refresh_expires_at = request.session.get("refresh_token_expires_at")

    if refresh_expires_at:
        try:
            refresh_dt = datetime.fromisoformat(refresh_expires_at)
            if datetime.now(refresh_dt.tzinfo) >= refresh_dt:
                print("[AUTO REFRESH] refresh_token expired: logout")
                request.session.clear()
                clear_auth_data()
                return
        except Exception as e:
            print(f"[CHECK TOKEN ERROR] refresh_token parse: {e}")

    # проверка access_token:
    expires_at = request.session.get("access_token_expires_at")

    if not expires_at:
        return

    try:
        expires_at = datetime.fromisoformat(expires_at)

        # обновление за 5 минут до конца жизни access_token
        if datetime.now() >= expires_at - timedelta(minutes=5):
            print("[AUTO REFRESH] access_token expires soon")

            await refresh_tokens(request)

    except Exception as e:
        print(f"[CHECK TOKEN ERROR] {e}")
