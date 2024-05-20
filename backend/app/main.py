from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .models.model import Course
from .models.model import ScienceCourse
from .models.model import CourseRecommendation, UserRegistration, UserLogin, ChangePassword, UserInDB, UserAddInfo, AddPrevRecoom, UserGetAllResponse
from typing import List  # Import List from the typing module
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import HTTPBearer
from .config.database import database
from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta
from fastapi import Body
from .config.database import user_collection
from typing import Annotated
from fastapi.security import HTTPAuthorizationCredentials
app = FastAPI()

oauth2_scheme = HTTPBearer()

from .routers.router import(

    fetch_recommend_courses,
    add_prev_recoms,
    register_user,
    authenticate_user,
    create_access_token,
    get_current_user,
    update_password,
    add_user_info,
    get_all_user,
    delete_user

    
)
#to allow frontend to access the backend
origins = ['https://localhost:3000']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 

#an example of a route
# @app.get("/")
# def read_root():
#      return {"Hello": "World"}
# @app.get("/items/")
# async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
#     return {"token": token}

@app.post("/user/login", tags=["User"])
async def login_for_access_token(user_data: UserLogin):
    user = await authenticate_user(user_data.username, user_data.password, user_collection)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, 
            "success": True}


@app.post("/user/register", tags=["User"])
async def register_user_endpoint(user_data: UserRegistration):
    response = await register_user(user_data)
    if response:
        return response
    else:
        raise HTTPException(404, "Cannot register user")
    

@app.post("/user/changePassword", tags=["User"])
async def change_password(user_data: ChangePassword, current_user: UserInDB = Depends(get_current_user)):
    if not user_data.new_password == user_data.confirm_password:
        raise HTTPException(400, "Passwords do not match")
    else:
        response = await update_password(user_data, current_user)
        if response:
            return response
        else:
            raise HTTPException(404, "Cannot change password")
    
        # Update user's password
        new_hashed_password = get_password_hash(change_data.new_password)
        await update_password(user.username, new_hashed_password, user_collection)
        return {"message": "Password updated successfully"}



@app.post("/user/addInfo", tags=["User"])
async def add_user_info_route(user_info: UserAddInfo, token: Annotated[str, Depends(oauth2_scheme)]):
    response = await add_user_info(user_info, token)
    if response:
        return response
    else:
        raise HTTPException(404, "Cannot add user info")


@app.post("/recommend/course", tags=["Recommend"])
async def get_course_recommendation(token: Annotated[str, Depends(oauth2_scheme)]):
    response = await fetch_recommend_courses(token)
    if response:
        return response
    else:
        raise HTTPException(404, "No courses found")


@app.post("/course/addRecommended", tags=["Course"]) 
async def add_course(courses: AddPrevRecoom, token: Annotated[str, Depends(oauth2_scheme)]):
    response = await add_prev_recoms(courses, token)
    if response:
        return response
    else:
        raise HTTPException(404, "Cannot add course")

@app.post("/user/getAll", response_model=UserGetAllResponse, tags=["User"])
async def get_all_user_handler(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response = await get_all_user(token)
    if response:
        return response
    else:
        raise HTTPException(404, "No users found")

@app.delete("/user/delete", tags=["User"])
async def delete_user_handler(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response = await delete_user(token)
    if response:
        return response
    else:
        raise HTTPException(404, "Cannot delete user")