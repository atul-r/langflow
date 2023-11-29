import os
import httpx
from sqlmodel import Session
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from langflow.services.getters import get_session
from langflow.api.v1.schemas import Token
from langflow.services.auth.utils import (
    authenticate_user,
    create_user_tokens,
    create_refresh_token,
    create_user_longterm_token,
    get_current_active_user,
)

from langflow.services.getters import get_settings_service

from starlette.requests import Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import HTMLResponse, RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
router = APIRouter(tags=["Login"])

scope = 'openid email profile'
client_id = os.environ.get('CLIENT_ID')
client_secret = os.environ.get('CLIENT_SECRET')
well_known_configuration_endpoint = f"{os.environ.get('ISSUER_URL')}/.well-known/openid-configuration"
token_endpoint = os.environ.get('TOKEN_ENDPOINT')
logout_endpoint = os.environ.get('LOGOUT_ENDPOINT')
post_logout_uri = os.environ.get('POST_LOGOUT_URI')
authentication_type = os.environ.get('LANGFLOW_AUTHENTICATION_TYPE')

print(f"client_id {client_id}")
print(f"client_secret {client_secret}")
print(f"well_known_configuration_endpoint {well_known_configuration_endpoint}")
print(f"token_endpoint {token_endpoint}")
print(f"logout_endpoint {logout_endpoint}")
print(f"post_logout_uri {post_logout_uri}")
print(f"authentication_type {authentication_type}")


oauth = OAuth()

oauth.register(
    name='client',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url=well_known_configuration_endpoint,
    client_kwargs={
        'scope': scope
    }
)

if authentication_type == 'oidc':
    @router.get('/login')
    async def login(request: Request):
        redirect_uri = request.url_for('callback')
        response = await oauth.client.authorize_redirect(request, redirect_uri)
        print(f'/login 0.7.3 response {response}')
        return response

    @router.get('/callback')
    async def callback(request: Request):
        try:
            token = await oauth.client.authorize_access_token(request)
            print(f'/callback 0.7.3 token')
        except OAuthError as error:
            return HTMLResponse(f'<h1>{error.error}</h1>')
        user = token.get('userinfo')
        response = RedirectResponse(url='/')
        response.set_cookie('id_tkn_lflw', token['id_token'])
        response.set_cookie('access_tkn_lflw', token['access_token'])
        response.set_cookie('refresh_tkn_lflw', token['refresh_token'])
        return response

    @router.get('/logout')
    async def logout(request: Request):
        print(f'/logout 0.7.3')
        try:
            response = RedirectResponse(f"{logout_endpoint}?id_token_hint={request.cookies['id_tkn_lflw']}&post_logout_redirect_uri={post_logout_uri}")
            response.delete_cookie('id_tkn_lflw')
            response.delete_cookie('access_tkn_lflw')
            response.delete_cookie('refresh_tkn_lflw')
            return response
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid request",
                headers={"WWW-Authenticate": "Bearer"},
            )
else:
    @router.post("/login", response_model=Token)
    async def login_to_get_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_session),
        # _: Session = Depends(get_current_active_user)
    ):
        try:
            user = authenticate_user(form_data.username, form_data.password, db)
        except Exception as exc:
            if isinstance(exc, HTTPException):
                raise exc
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            ) from exc

        if user:
            return create_user_tokens(user_id=user.id, db=db, update_last_login=True)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )


@router.get("/auto_login")
async def auto_login(
    db: Session = Depends(get_session), settings_service=Depends(get_settings_service)
):
    if settings_service.auth_settings.AUTO_LOGIN:
        return create_user_longterm_token(db)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "message": "Auto login is disabled. Please enable it in the settings",
            "auto_login": False,
        },
    )

@router.get("/auth_type")
async def auth_type(
    settings_service=Depends(get_settings_service)
):
    print(f"from new auth_type ... v 0.7.3 {settings_service.auth_settings.AUTHENTICATION_TYPE}" )
    try:
        if settings_service.auth_settings.AUTHENTICATION_TYPE:
            return {
                "authentication_type": settings_service.auth_settings.AUTHENTICATION_TYPE
            }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            headers={"WWW-Authenticate": "Bearer"},
        )

if authentication_type == 'oidc':
    @router.post("/refresh")
    async def refresh_token(token: str):
        print("from new refresh ... v 0.7.3")
        if token:
            try:
                print(f"token query param {token}")
                data = {
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'grant_type': 'refresh_token',
                    'refresh_token': token,
                }
                print(f"data {data}")
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                print(f"fetching new acc token")
                async with httpx.AsyncClient() as client:
                    response = await client.post(token_endpoint, data=data, headers=headers)
                response.raise_for_status()
                access_token = response.json()['access_token']
                refresh_token = response.json()['refresh_token']
                print(f"retuning new acc token {access_token}, refresh {refresh_token}")
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                }
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
else:
    @router.post("/refresh")
    async def refresh_token(
        token: str, current_user: Session = Depends(get_current_active_user)
    ):
        if token:
            return create_refresh_token(token)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
