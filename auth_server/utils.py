# (c) Copyright Datacraft, 2026
from uuid import UUID

from fastapi import Request, FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
import jwt

from .config import Settings

app = FastAPI()
settings = Settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


def raise_on_empty(**kwargs):
    """Raises ValueError exception if at least one value of the
    key in kwargs dictionary is None
    """
    for key, value in kwargs.items():
        if value is None:
            raise ValueError(
                 f"{key} is expected to be non-empty"
            )


def from_header(request: Request) -> str | None:
    authorization = request.headers.get("Authorization")
    scheme, token = get_authorization_scheme_param(authorization)

    if not authorization or scheme.lower() != "bearer":
        return None

    return token


def from_cookie(request: Request) -> str | None:
    cookie_name = settings.cookie_name
    return request.cookies.get(cookie_name, None)


def get_token(request: Request) -> str | None:
    return from_cookie(request) or from_header(request)


async def get_current_user_id(request: Request) -> UUID:
    """Extract current user ID from JWT token."""
    token = get_token(request)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.token_algorithm],
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
        return UUID(user_id)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.DecodeError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
