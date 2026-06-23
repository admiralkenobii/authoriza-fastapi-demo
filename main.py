import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from auth import router as auth_router
from oauth_client import setup_oauth


# загрузка переменных окружения
load_dotenv()

# конфиг
SECRET_KEY = os.getenv("SECRET_KEY")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
OIDC_METADATA_URL = (
    "https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/"
    "oidc/.well-known/openid-configuration"
)

# настройка OAuth-клиента
setup_oauth(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=OIDC_METADATA_URL,
)


# проверка при запуске приложения
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Application started")
    yield
    print("Application stopped")


# создание приложения
app = FastAPI(lifespan=lifespan)

# подключение сессий
# + middleware для поддержки сессий в Authlib
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
)

# подключение маршрутов авторизации
app.include_router(auth_router)
