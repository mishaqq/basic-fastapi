from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from typing import List, Annotated
import models
from database import SessionLocal, engine
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError
SECRET = "692231733f2092790aff8c5aa3a874480775d5c241cf09de0a876344350abf70"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    

models.Base.metadata.create_all(bind=engine)

def get_db():
        db = SessionLocal()
        try:
                yield db
        finally:
                db.close()

db_dependency = Annotated[Session, Depends(get_db)]


class User(BaseModel):
    username: str
    email: EmailStr | None = None

class UserInDB(User):
    hashed_password: str | None = None
    id: str | None = None

class UserIn(User):
    password: str

class HostedGame(BaseModel):
        title: str
        startDate: datetime | None = None
        isActive: bool 
        host: str | None = None
        
        class Config:
                from_attributes = True
def veryfy_password(password, hashed_password):
        return pwd_context.verify(password, hashed_password)

def get_password_hash(password):
        return pwd_context.hash(password)
async def authenticate_user(username: str, password: str, db: Session):
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user: 
                return None
        if not veryfy_password(password, user.hashed_password):
                return None
        return UserInDB(id=user.id, username=user.username, email=user.email, hashed_password=user.hashed_password)
        
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: db_dependency) -> UserInDB:
        user = await decode_token(token, db)
        if not user:
                raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
                )
        return user
def create_access_token(data: dict, expires_delta: timedelta | None = None):
        to_encode = data.copy()
        if expires_delta:
                expire = datetime.utcnow() + expires_delta
        else:
                expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
        return encoded_jwt


async def decode_token(token: str, db: Session) -> UserInDB | None:
        credentials_exception = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
                )   
        try:
               payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
               username = payload.get("sub")
              
               if username is None:
                       raise credentials_exception
        except InvalidTokenError:
                raise credentials_exception       
        user_from_db = db.query(models.User).filter(models.User.username == username).first()
        if not user_from_db:
                return None
        return UserInDB( username=user_from_db.username, email=user_from_db.email, id=user_from_db.id)

@app.get("/")
async def helloWorld(token: Annotated[str, Depends(oauth2_scheme)]):
        return {"token": token}

#db.query(models.User).filter(models.User.username == form_data.username).first()

@app.post('/token')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
        user = await authenticate_user(form_data.username, form_data.password, db)
        if not user:
               raise HTTPException(status_code=400, detail="Incorrect username or password")
        user_db = UserInDB( username=user.username, email=user.email, hashed_password=user.hashed_password)
        access_token = create_access_token(data= {"sub" : user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

        
        return {"access_token": access_token, "token_type": "bearer"}


@app.get('/user/me', response_model=UserInDB)
async def read_users_me(current_user: Annotated[UserInDB, Depends(get_current_user)]):
       return current_user


@app.post("/fake_register")
async def fake_register(user: UserIn, db: db_dependency):
        db_User = models.User(username=user.username, hashed_password=get_password_hash(user.password), email=user.email)
        db.add(db_User)
        db.commit()

        return {"user": user}

@app.post("/add_game", response_model=HostedGame)
async def addGame(current_user: Annotated[UserInDB, Depends(get_current_user)], db: db_dependency, game: HostedGame):
       db_hosted_game = models.HostedGame(title=game.title, startDate=datetime.now(timezone.utc), isActive=game.isActive, host=current_user.id)
       db.add(db_hosted_game)
       db.commit()
       db.refresh(db_hosted_game)
       return  db_hosted_game

@app.get("/get_hosted_games", response_model=List[HostedGame])
async def getHostedGames(current_user: Annotated[UserInDB, Depends(get_current_user)], db: db_dependency):
       return db.query(models.HostedGame).filter(models.HostedGame.host == current_user.id).all()