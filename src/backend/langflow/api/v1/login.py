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

client_id = 'langflow-client'
client_secret = 'LQOhDSKRopEczKRCOl7eDuYnozGkJ51H'
scope = 'openid email profile'

oauth = OAuth()

CONF_URL = 'https://keycloak.css-da-02.hitachi-lumada.io/realms/langflow/.well-known/openid-configuration'
oauth.register(
    name='client',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': scope
    }
)

@router.get('/login')
async def login(request: Request):
    redirect_uri = request.url_for('callback')
    response = await oauth.client.authorize_redirect(request, redirect_uri)
    print(f'/login response {response}')
    return response

@router.get('/callback')
async def callback(request: Request):
    try:
        token = await oauth.client.authorize_access_token(request)
        print(f'/callback token {token}')
    except OAuthError as error:
        return HTMLResponse(f'<h1>{error.error}</h1>')
    user = token.get('userinfo')
    # if user:
    #     request.session['user'] = dict(user)
    response = RedirectResponse(url='/')
    response.set_cookie('access_tkn_lflw', token['access_token'])
    response.set_cookie('refresh_tkn_lflw', token['refresh_token'])
    return response




@router.post("/login-xyz", response_model=Token)
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
