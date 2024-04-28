from fastapi import FastAPI
from pymongo import MongoClient
import os

app = FastAPI()

# Load the MongoDB connection string from an environment variable
connection_string = os.getenv("MONGODB_CONNECTION_STRING")

# Create a MongoClient
client = MongoClient(connection_string)

# Connect to your database (replace "myDatabase" with your database name)
db = client.myDatabase

@app.get("/")
def read_root():
    try:
        # Try to fetch a document from the database
        db.items.find_one()
        return {"status": "Connected to MongoDB"}
    except Exception as e:
        return {"status": "Failed to connect to MongoDB", "error": str(e)}

@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = None):
    # Query the database for the item
    item = db.items.find_one({"_id": item_id})
    if item is None:
        return {"item_id": item_id, "q": q}
    else:
        return item