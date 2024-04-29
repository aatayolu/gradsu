from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI, HTTPException

app = FastAPI()

@app.get("/")
def read_root():
    return {"Sorrow": "Pain"}

@app.get("/check_connection")
async def check_connection():
    client = AsyncIOMotorClient("mongodb+srv://zeynepkrtls01:ZRAZ2x5rw9AXMllc@sugradcluster.aro7tnh.mongodb.net/")
    try:
        # The ismaster command is cheap and does not require auth.
        await client.admin.command('ismaster')
        return {"status": "MongoDB connection is successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))