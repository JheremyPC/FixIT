from fastapi import HTTPException, status

def forbidden(detail="No tiene permiso para esta operación"):
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

def not_found(name="Recurso"):
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{name} no encontrado")

