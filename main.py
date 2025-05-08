from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Annotated
import models
from database import SessionLocal, engine
from sqlalchemy.orm import Session

app = FastAPI()
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

class HostedGame(BaseModel):
    title: str
    startDate: str
    isActive: bool


@app.get("/")
def helloWorld():
        return {"hello": "world"}

@app.post("/addUser")
async def addUser(user: User, db: db_dependency):
       db_User = models.User(username = user.username)
       db.add(db_User)
       db.commit()

       return {"user": user}

# @app.get("/get-item/{item_id}", response_model=Item)
# def getItem(id : int) -> Item:
# 	if id < len(items):
# 		return items[id]
# 	else:
# 		raise HTTPException(status_code=404, detail="Item not found")

# @app.get("/items")
# def getItems(limit: int = 10):
#         return items[0:limit]