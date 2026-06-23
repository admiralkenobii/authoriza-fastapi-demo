from authlib.integrations.starlette_client import OAuth


oauth = OAuth()


# настройка клиента авторизы
def setup_oauth(
    client_id: str | None,
    client_secret: str | None,
    server_metadata_url: str,
) -> OAuth:
    oauth.register(
        name="authoriza",
        client_id=client_id,
        client_secret=client_secret,
        # Используем Discovery Endpoint
        server_metadata_url=server_metadata_url,
        token_endpoint_auth_method="client_secret_basic",
        client_kwargs={
            # offline_access для получения refresh_token
            "scope": "openid offline_access profile email",
            # Включаем PKCE
            "code_challenge_method": "S256",
        },
    )

    return oauth
