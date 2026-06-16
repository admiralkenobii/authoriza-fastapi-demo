import os
from fastapi import FastAPI, Request
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

app = FastAPI()

# middleware для поддержки сессий в Authlib
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "super-secret-change-me")
)

oauth = OAuth()

# Регистрируем Авторизу как OIDC-провайдера
oauth.register(
    name='authoriza',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    # Используем Discovery Endpoint
    server_metadata_url='https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/.well-known/openid-configuration',
    client_kwargs={
        # offline_access обычно нужен для получения refresh_token
        'scope': 'openid profile email offline_access',
        # Включаем PKCE (Authorization Code Flow c PKCE)
        'code_challenge_method': 'S256'
    }
)


@app.get("/")
async def home(request: Request):
    # Пытаемся достать пользователя из сессии
    user = request.session.get('user')
    if user:
        return {"message": f"Привет, {user.get('name', 'Пользователь')}!", "userinfo": user}
    return {"message": "Hello!"}


@app.get("/login")
async def login(request: Request):
    # URL куда Авториза вернет пользователя после успешного входа
    redirect_uri = request.url_for('auth')
    # redirect_uri = "http://127.0.0.1:8000/auth"

    # Authlib сам сгенерирует PKCE (code_verifier/code_challenge) и перенаправит куда нужно
    return await oauth.authoriza.authorize_redirect(request, redirect_uri)


@app.get("/auth")
async def auth(request: Request):
    # Обмениваем временный authorization_code на токены (Token Endpoint)
    token = await oauth.authoriza.authorize_access_token(request)

    # Сохраняем токены и данные пользователя в сессию (для выполнения требований ТЗ)
    request.session['token'] = token

    # Authlib автоматически парсит ID Token и складывает claims в userinfo
    userinfo = token.get('userinfo')
    if userinfo:
        request.session['user'] = userinfo

    return {
        "message": "Успешный вход!",
        "token_endpoint_response": token  # Здесь будут access_token, id_token, refresh_token и т.д.
    }
