from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from auth_storage import clear_auth_data, save_auth_data
from oauth_client import oauth
from session_service import restore_session
from token_service import check_token, decode_token_payload, refresh_tokens, get_refresh_expires_at


router = APIRouter()
templates = Jinja2Templates(directory="templates")


# главная страница
@router.get("/")
async def home(request: Request):
    await restore_session(request)  # восстановление сессии
    await check_token(request)

    token = request.session.get("token")
    user = request.session.get("user")
    login_time = request.session.get("login_time")

    id_token_payload = None
    access_token_payload = None

    if token:
        # Декодируем ID Token для отображения
        id_token_payload = decode_token_payload(token.get("id_token"))

        # Декодируем Access Token для отображения
        access_token_payload = decode_token_payload(token.get("access_token"))

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "authenticated": token is not None,
            "user": user,
            "id_token_payload": id_token_payload,
            "access_token_payload": access_token_payload,
            "login_time": login_time,
            "userinfo_received_at": request.session.get("userinfo_received_at"),
        },
    )


@router.get("/login")
async def login(request: Request):
    # URL куда вернет пользователя после успешного входа
    redirect_uri = request.url_for("callback")
    # Authlib сгенерирует PKCE и перенаправит
    return await oauth.authoriza.authorize_redirect(
        request,
        redirect_uri
    )


@router.get("/callback")
async def callback(request: Request):
    # Пользователь или провайдер вернул ошибку
    error = request.query_params.get("error")
    if error:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": error,
                "error_description": request.query_params.get("error_description"),
            },
        )

    try:
        # Обмен code на токены
        token = await oauth.authoriza.authorize_access_token(request)

        # если токен не получен:
        if not token:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "Token exchange failed",
                },
            )

        # Получаем UserInfo
        user = token.get("userinfo")

        # Если userinfo не пришёл автоматически запросим вручную
        if not user:
            user = await oauth.authoriza.userinfo(token=token)

        # Время получения UserInfo
        request.session["userinfo_received_at"] = datetime.now().isoformat()

        # Создаём пользовательскую сессию и сохраняем в неё
        request.session["token"] = token
        request.session["user"] = dict(user) if user else None
        request.session["login_time"] = datetime.now().isoformat()
        # время истечения токена
        request.session["access_token_expires_at"] = (
            datetime.now(timezone.utc) + timedelta(seconds=token["expires_in"])
        ).isoformat()

        # пытаемся достать срок жизни refresh_token
        if "refresh_expires_in" in token:  # если в самом токене нет
            request.session["refresh_token_expires_at"] = (
                datetime.now(timezone.utc) + timedelta(seconds=token["refresh_expires_in"])
            ).isoformat()
        else:  # то декодируем как JWT
            request.session["refresh_token_expires_at"] = get_refresh_expires_at(token)

        # сохранение данных после логина
        save_auth_data(
            request.session["token"],
            request.session["user"],
            request.session["login_time"],
            request.session["access_token_expires_at"],
            request.session["refresh_token_expires_at"],
            request.session["userinfo_received_at"],
        )

        return RedirectResponse(url="/")

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e),
            },
        )


@router.get("/status")
async def status(request: Request):
    await restore_session(request)  # восстановление сессии
    await check_token(request)

    token = request.session.get("token")
    user = request.session.get("user")

    if not token:
        return {
            "authenticated": False,
        }

    return {
        "authenticated": True,
        "login_time": request.session.get("login_time"),
        "last_refresh_time": request.session.get("last_refresh_time"),
        "access_token_expires_at": request.session.get("access_token_expires_at"),
        "refresh_token_expires_at": request.session.get("refresh_token_expires_at"),
        "userinfo_received_at": request.session.get("userinfo_received_at"),
        "user": user,
        "token_type": token.get("token_type"),
        "scope": token.get("scope"),
    }


@router.get("/refresh")
async def refresh(request: Request):
    try:
        ok = await refresh_tokens(request)

        if not ok:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "message": "User is not authenticated",
                },
            )

        return RedirectResponse(url="/")

    except Exception as e:
        error_str = str(e)

        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": error_str,
            },
        )


# выход из аккаунта
@router.get("/logout")
async def logout(request: Request):
    request.session.clear()  # очищение сессии
    clear_auth_data()  # удаление файла сессии (json)
    return RedirectResponse(url="/")
