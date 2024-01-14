from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from typing import Annotated

import crud
import models
import schemas
from auth import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, Token, authenticate_user, get_current_active_user, \
    get_password_hash
from database import engine, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

models.Base.metadata.create_all(bind=engine)

app = FastAPI()


@app.post("/login")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/register", response_model=schemas.User)
def create_user(user: Annotated[schemas.UserCreate, Depends()], db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    return crud.create_user(db=db, user=user, hashed_password=hashed_password)


@app.get("/users/me", response_model=schemas.User)
def read_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)], db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=current_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/users/{user_id}/items/", response_model=schemas.Item)
def create_item_for_user(
        current_user: Annotated[schemas.User, Depends(get_current_active_user)],
        item: Annotated[schemas.ItemCreate, Depends()],
        db: Session = Depends(get_db)
):
    return crud.create_user_item(db=db, item=item, user_id=current_user.id)


@app.get("/items/", response_model=list[schemas.Item])
def read_items(current_user: Annotated[schemas.User, Depends(get_current_active_user)], skip: int = 0, limit: int = 100,
               db: Session = Depends(get_db)):
    items = crud.get_items(db, user_id=current_user.id, skip=skip, limit=limit)
    return items
