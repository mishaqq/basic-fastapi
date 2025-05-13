from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from typing import List, Annotated
import models
from database import SessionLocal, engine
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    

models.Base.metadata.create_all(bind=engine)

def get_db():
        db = SessionLocal()
        try:
                yield db
        finally:
                db.close()

db_dependency = Annotated[Session, Depends(get_db)]


class User(BaseModel):
    id: str
    username: str
    email: EmailStr | None = None

class UserInDB(User):
    hashed_password: str

class UserIn(User):
    password: str


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: db_dependency) -> User:
        user = await fake_decode_token(token, db)
        if not user:
                raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
                )
        return user
    
async def fake_decode_token(token: str, db: Session) -> User | None:
        user_from_db = db.query(models.User).filter(models.User.username == token).first()
        if not user_from_db:
                return None
        return User(id=user_from_db.id, username=user_from_db.username, email=user_from_db.email)

@app.get("/")
async def helloWorld(token: Annotated[str, Depends(oauth2_scheme)]):
        return {"token": token}


@app.post('/token')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
        user_dict = db.query(models.User).filter(models.User.username == form_data.username).first()
        if not user_dict:
               raise HTTPException(status_code=400, detail="Incorrect username or password")
        user_db = UserInDB(id=user_dict.id, username=user_dict.username, email=user_dict.email, hashed_password=user_dict.hashed_password)
        hashed_password = user_db.hashed_password
        if hashed_password != form_data.password:
               raise HTTPException(status_code=400, detail="Incorrect username or password")
        return {"access_token": user_db.username, "token_type": "bearer"}


@app.get('/user/me', response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
       return current_user
@app.post("/fake_register")
async def fake_register(user: UserIn, db: db_dependency):
        db_User = models.User(username=user.username, hashed_password=user.password)
        db.add(db_User)
        db.commit()

        return {"user": user}

# @app.post("/addUser")
# async def addUser(user: User, db: db_dependency):
#        db_User = models.User(username = user.username)
#        db.add(db_User)
#        db.commit()

#        return {"user": user}

