from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models import User

security = HTTPBearer(auto_error=False)
ALGORITHM = "HS256"
# Compared against when the account does not exist, so a failed login costs the same either way
# (no user enumeration through response times).
DUMMY_HASH = bcrypt.hashpw(b"fixit-dummy-password", bcrypt.gensalt()).decode()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def create_token(user: User, token_type: str) -> str:
    lifetime = timedelta(minutes=settings.jwt_access_minutes) if token_type == "access" else timedelta(days=settings.jwt_refresh_days)
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user.id, "role": user.role.code, "type": token_type, "iat": now, "exp": now + lifetime}, settings.jwt_secret_key, algorithm=ALGORITHM)

def decode_token(token: str, token_type: str) -> dict:
    """Claims of a valid, unexpired token of the given type; raises JWTError otherwise. Only HS256 is accepted."""
    claims = jwt.decode(token, settings.jwt_secret_key, algorithms=[ALGORITHM], options={"require": ["exp", "iat", "sub"]})
    if claims.get("type") != token_type: raise JWTError("Tipo de token inválido")
    return claims

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticación requerida")
    try:
        user = db.get(User, decode_token(credentials.credentials, "access").get("sub"))
    except JWTError:
        user = None
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión inválida o usuario inactivo")
    return user

def require_roles(*codes: str):
    def checker(user: User = Depends(current_user)) -> User:
        if user.role.code not in codes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Rol sin autorización")
        return user
    return checker
