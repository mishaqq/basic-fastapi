from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class Item(BaseModel):
    text : str = None
    isDone : bool = None

items = [ ]


@app.get("/")
def helloWorld():
        return {"hello": "world"}

@app.post("/add-item", response_model=list[Item])
def createItem(item: Item):
        items.append(item)
        return items


@app.get("/get-item/{item_id}", response_model=Item)
def getItem(id : int) -> Item:
	if id < len(items):
		return items[id]
	else:
		raise HTTPException(status_code=404, detail="Item not found")

@app.get("/items")
def getItems(limit: int = 10):
        return items[0:limit]