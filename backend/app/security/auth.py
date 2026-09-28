from datetime import datetime, timedelta, timezone
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models import User

security = HTTPBearer(auto_error=False)
ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def create_token(user: User, token_type: str) -> str:
    lifetime = timedelta(minutes=settings.jwt_access_minutes) if token_type == "access" else timedelta(days=settings.jwt_refresh_days)
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user.id, "role": user.role.code, "type": token_type, "iat": now, "exp": now + lifetime}, settings.jwt_secret_key, algorithm=ALGORITHM)

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticación requerida")
    try:
        payload = jwt.decode(credentials.credentials, settings.jwt_secret_key, algorithms=[ALGORITHM])
        if payload.get("type") != "access": raise JWTError()
        user = db.get(User, payload.get("sub"))
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
