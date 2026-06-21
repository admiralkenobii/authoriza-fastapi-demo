import os
import jwt
from fastapi import FastAPI, Request
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from fastapi.responses import JSONResponse, RedirectResponse
from datetime import datetime
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

# загрузка переменных окружения
load_dotenv()

# создание приложения
app = FastAPI()

# подключение сессий
# + middleware для поддержки сессий в Authlib
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY")
)

oauth = OAuth() # настройка OAuth-клиента

# Регистрируем авторизу
oauth.register(
    name='authoriza',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    # Используем Discovery Endpoint
    server_metadata_url='https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/.well-known/openid-configuration',
    token_endpoint_auth_method='client_secret_basic',
    client_kwargs={
        # offline_access для получения refresh_token
        'scope': 'openid offline_access profile email',
        # Включаем PKCE
        'code_challenge_method': 'S256'
    }
)


# главная страница
@app.get("/")
async def home(request: Request):
    token = request.session.get("token")
    user = request.session.get("user")
    login_time = request.session.get("login_time")

    id_token_payload = None
    access_token_payload = None

    if token:
        # Декодируем ID Token для отображения
        if token.get("id_token"):
            try:
                id_token_payload = jwt.decode(
                    token["id_token"], options={"verify_signature": False}
                )
            except Exception:
                pass

        # Декодируем Access Token для отображения
        if token.get("access_token"):
            try:
                access_token_payload = jwt.decode(
                    token["access_token"], options={"verify_signature": False}
                )
            except Exception:
                pass

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "authenticated": token is not None,
            "token": token,
            "user": user,
            "id_token_payload": id_token_payload,
            "access_token_payload": access_token_payload,
            "login_time": login_time,
        },
    )


# Временно для отладки
@app.get("/debug")
async def debug(request: Request):
    return {
        "client_id": os.getenv('CLIENT_ID'),
        "client_secret_exists": bool(os.getenv('CLIENT_SECRET')),
        "client_secret_length": len(os.getenv('CLIENT_SECRET', '')),
    }


@app.get("/login")
async def login(request: Request):
    # URL куда вернет пользователя после успешного входа
    redirect_uri = request.url_for('callback')
    # Authlib сгенерирует PKCE и перенаправит
    return await oauth.authoriza.authorize_redirect(request, redirect_uri, prompt="consent")


@app.get("/callback")
async def callback(request: Request):
    # Пользователь или провайдер вернул ошибку
    error = request.query_params.get("error")
    if error:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": error,
                "error_description": request.query_params.get(
                    "error_description"
                )
            }
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
                    "message": "Token exchange failed"
                }
            )

        # Получаем UserInfo
        user = token.get("userinfo")

        # Если userinfo не пришёл автоматически запросим вручную
        if not user:
            user = await oauth.authoriza.userinfo(token=token)

        # Время получения UserInfo
        userinfo_received_at = datetime.now().isoformat()

        # Декодируем ID Token
        id_token_payload = None
        if token.get("id_token"):
            id_token_payload = jwt.decode(
                token["id_token"],
                options={"verify_signature": False}
            )

        # Декодируем Access Token
        access_token_payload = None
        if token.get("access_token"):
            access_token_payload = jwt.decode(
                token["access_token"],
                options={"verify_signature": False}
            )

        # Создаём пользовательскую сессию и сохраняем в неё
        request.session["token"] = token
        request.session["user"] = dict(user) if user else None
        # сохранение времени входа
        request.session["login_time"] = datetime.now().isoformat()

        return RedirectResponse(url="/")
        # return {
        #     "status": "success",
        #     "token": {
        #         "access_token": token.get("access_token"),
        #         "id_token": token.get("id_token"),
        #         "refresh_token": token.get("refresh_token"),
        #         "expires_in": token.get("expires_in"),
        #         "token_type": token.get("token_type"),
        #         "scope": token.get("scope"),
        #     },
        #     "id_token_payload": id_token_payload,
        #     "access_token_payload": access_token_payload,
        #     "userinfo": user,
        #     "userinfo_received_at": userinfo_received_at
        # }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e)
            }
        )


@app.get("/status")
async def status(request: Request):
    token = request.session.get("token")
    user = request.session.get("user")

    if not token:
        return {
            "authenticated": False
        }

    expires_in = token.get("expires_in")

    return {
        "authenticated": True,
        "login_time": request.session.get("login_time"),
        "user": user,
        "token_type": token.get("token_type"),
        "scope": token.get("scope"),
        "access_token_expires_in": expires_in
    }


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/refresh")
async def refresh(request: Request):
    token = request.session.get("token")

    if not token:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": "User is not authenticated"}
        )

    old_refresh_token = token.get("refresh_token")
    if not old_refresh_token:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Refresh token not found"}
        )

    try:
        # Получаем актуальную конфигурацию
        metadata = await oauth.authoriza.load_server_metadata()
        token_endpoint = metadata.get("token_endpoint")
        userinfo_endpoint = metadata.get("userinfo_endpoint")

        # обновляем токены
        async with oauth.authoriza._get_oauth_client(**metadata) as client:
            new_token = await client.refresh_token(
                url=token_endpoint,
                refresh_token=old_refresh_token
            )

        # сохраняем новые токены немедленно
        request.session["token"] = new_token
        request.session["last_refresh_time"] = datetime.now().isoformat()

        # пытаемся обновить UserInfo
        access_token = new_token.get("access_token")

        if access_token and userinfo_endpoint:
            try:
                headers = {"Authorization": f"Bearer {access_token}"}

                async with oauth.authoriza._get_oauth_client(**metadata) as client2:
                    resp = await client2.get(userinfo_endpoint, headers=headers)

                if resp.status_code == 200:
                    user_data = resp.json()
                    request.session["user"] = user_data
                else:
                    # логируем
                    print(f"[REFRESH] UserInfo вернул {resp.status_code}. Токены уже обновлены.")
            except Exception as ui_err:
                # игнорируем ошибку UserInfo
                print(f"[REFRESH] Не удалось обновить UserInfo: {ui_err}")

        # на главную страницу
        return RedirectResponse(url="/")

    except Exception as e:
        error_str = str(e)
        print(f"[REFRESH ERROR] {error_str}")

        # Если ошибка именно при обновлении refresh_token
        if "401" in error_str or "Unauthorized" in error_str:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "message": "Refresh token is invalid or expired",
                    "details": error_str,
                    "recommendation": "Выполните /logout и войдите заново, чтобы получить новый refresh_token."
                }
            )

        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": error_str}
        )
