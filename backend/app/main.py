from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .models.model import Course
from .models.model import ScienceCourse
from .models.model import CourseRecommendation, UserRegistration, UserLogin, ChangePassword, UserInDB, UserAddInfo, AddPrevRecoom, UserGetAllResponse, SpecificRecom, CourseAdd
from typing import List  # Import List from the typing module
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import HTTPBearer
from .config.database import database
from .config.database import client
from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta
from fastapi import Body
from .config.database import user_collection
from typing import Annotated
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

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
    delete_user,
    fetch_recommend_specific_courses,
    process_recommendation,
    process_content_recommendation,
    fetch_top_courses,
    add_course_info_user,
    fetch_least_courses

    
)
#to allow frontend to access the backend
origins = ['https://localhost:3000']

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 


@app.post("/user/login", tags=["User"])
async def login_for_access_token(user_data: UserLogin):
    user = await authenticate_user(user_data.username, user_data.password, user_collection)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, 
            "pdf_uploaded": user.pdf_uploaded,
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
async def add_user_info_route(user_info: UserAddInfo, token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response = await add_user_info(user_info, token)
    if response:
        return response
    else:
        raise HTTPException(404, "Cannot add user info")


@app.post("/recommend/course", tags=["Recommend"])
async def get_course_recommendation(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
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

@app.post("/user/getAll", response_model=UserGetAllResponse, tags=["User"], summary="Get all user info")
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
    

@app.post("/recommend/specificCourse", tags=["Recommend"], summary="Recommend specific courses")
async def get_specific_course_recommendation(request: SpecificRecom, token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response = await fetch_recommend_specific_courses(request, token)
    if response:
        return response
    else:
        raise HTTPException(404, "No courses found")


@app.post("/recommend/collabrativeFiltering", tags=["Recommend"], summary="Recommend courses using collabrative filtering")
async def recommend_courses(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    return await process_recommendation(token)


@app.post("/recommend/contentBased", tags=["Recommend"], summary="Recommend courses using content based filtering")
async def recommend_courses(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    return await process_content_recommendation(token)

@app.get("/course/getTop", tags=["Course"], summary="Get top 3 courses")
async def get_top_courses(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response =  await fetch_top_courses(token)
    if response:
        return response
    else:
        raise HTTPException(404, "No courses found")
    

@app.post("/course/add", tags=["Course"], summary="Add course to user entity")
async def add_course(course: CourseAdd, token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response = await add_course_info_user(course, token)
    if response:
        return response
    else:
        raise HTTPException(404, "Cannot add course")
    

@app.get("/course/getLeast", tags=["Course"])
async def get_top_courses(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    response =  await fetch_least_courses(token)
    if response:
        return response
    else:
        raise HTTPException(404, "No courses found")