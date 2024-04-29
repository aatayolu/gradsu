import os
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.get("/")
def read_root():
    return {"Sorrow": "Pain"}


@app.get("/check_connection")
def check_connection():
    try:
        client = MongoClient(os.getenv("MONGODB_URL"))
        # Try to list databases, which will check the connection
        client.list_database_names()
        return {"status": "MongoDB connection is successful"}
    except PyMongoError as e:
        return {"status": "MongoDB connection failed", "detail": str(e)}