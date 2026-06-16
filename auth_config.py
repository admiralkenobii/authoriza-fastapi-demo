from dotenv import load_dotenv
import os

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
OIDC_DISCOVERY_URL = os.getenv("OIDC_DISCOVERY_URL")
REDIRECT_URI = os.getenv("REDIRECT_URI")
