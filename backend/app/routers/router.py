from ..models.model import Course
from ..models.model import CourseRecommendation
from ..models.model import ScienceCourse, UserRegistration, User, UserInDB, ChangePassword, UserAddInfo, UserDetails, AddPrevRecoom, UserGetAllResponse, SpecificRecom, LoginData, CourseAdd, DeleteUser
from typing import List  # Import List from the typing module
from fastapi import APIRouter
from ..config.database import cs_2018_fall
from ..config.database import user_collection, get_program_collection
from bson import ObjectId #this is what mongodb uses to be able to identify the id that it creates itself
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, HTTPAuthorizationCredentials, HTTPBearer
from ..config.database import database
from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta
from fastapi import Body
import re
from collections import Counter
import numpy as np
from jose import JWTError, jwt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import LabelEncoder
from scipy.sparse.linalg import svds
SECRET_KEY = "83daa0256a2289b0fb23693bf1f6034d44396675749244721a2b20e896e1662"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
outh2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_scheme = HTTPBearer()
router = APIRouter()

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def register_user(user_data: UserRegistration):
    # Check if username or email already exists
    existing_user = await user_collection.find_one({"$or": [{"username": user_data.username}, {"email": user_data.email}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Hash the password
    hashed_password = pwd_context.hash(user_data.password)
    # Replace the plain text password with the hashed one
    user_data_dict = user_data.model_dump()
    user_data_dict['password'] = hashed_password
    user_data_dict['first_name'] = user_data_dict['first_name'].capitalize()
    user_data_dict['last_name'] = user_data_dict['last_name'].capitalize()
    
    # Add additional fields to the user data dictionary
    user_data_dict['admission_year'] = ""
    user_data_dict['area_courses'] = []
    user_data_dict['free_courses'] = []
    user_data_dict['required_courses'] = []
    user_data_dict['core_courses'] = []
    user_data_dict['science_courses'] = []
    user_data_dict['university_courses'] = []
    user_data_dict['degree_program'] = ""
    user_data_dict['double_major'] = ""
    user_data_dict['minor'] = ""
    user_data_dict["pdf_uploaded"] = False
    user_data_dict["recommendations"] = []


    # Insert user data into MongoDB
    user_id = (await user_collection.insert_one(user_data_dict)).inserted_id
    
    return {"message": "User registered successfully",
            "success": True}


# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to create access token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to get user by username
async def get_user(username: str, user_collection):
    user = await user_collection.find_one({"username": username})
    if user:
        return UserInDB(**user)
    return None

async def get_user_for_login(username: str, user_collection):
    user = await user_collection.find_one({"username": username})
    if user:
        return LoginData(**user)
    return None


async def get_user_info(username: str) -> UserInDB:
    try:
        user = await user_collection.find_one({"username": username})
        if user:
            return UserInDB(**user)
    except Exception as e:
        # Handle exceptions such as database errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user information",
        )

    # If the user does not exist, raise HTTPException
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with username '{username}' not found",
    )



# Function to authenticate user
async def authenticate_user(username: str, password: str, user_collection):
    user = await get_user_for_login(username, user_collection)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

async def get_current_user_details(credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme))-> UserDetails :
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await user_collection.find_one({"username": username})
        #print("USER IS: ", user)
        if user:
            pdf_info = user.get("pdf_uploaded")
            if pdf_info == False:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Not enough student information found",
                )
            else:
                return UserDetails(**user)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_all_user(token: HTTPAuthorizationCredentials):
    try:
        token_str = token.credentials  # Access the token string
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await user_collection.find_one({"username": username})
        #print("USER IS: ", user)
        if user:
            pdf_info = user.get("pdf_uploaded")
            if pdf_info == False:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Not enough student information found",
                )
            else:
                return UserGetAllResponse(**user)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)) -> UserInDB:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await user_collection.find_one({"username": username})
        if user:
            return UserInDB(**user)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
def insert_space(course_code):
    # Check if the input already contains a space
    if ' ' in course_code:
        return course_code  # If there is already a space, return the unchanged course code
    
    # Convert to uppercase
    course_code = course_code.upper()
    
    # Use regular expression to insert space before the first digit
    modified_course_code = re.sub(r'(\D)(?=\d)', r'\1 ', course_code)
    
    return modified_course_code

async def add_prev_recoms(courses: AddPrevRecoom, token: str):
    current_user = await get_current_user(token)
    user_collection = database.get_collection("user")  # Assuming user_collection is obtained from somewhere
    #print("current user is: ", current_user)
    
    for course_list in courses.courses:  # Iterate over each list of courses
        for course_info_str in course_list:  # Iterate over each course info string in the list
            section = "0"  # Initialize section variable before processing each course
            
            course_info_str = course_info_str.strip()  # Extract the course info string
            #print("course info str is: ", course_info_str)
            words = course_info_str.split()
            third_word = words[2]
            print("third word is: ", third_word)
            
            
            # Check if there's a day immediately after the space after the course code
            course_code_end = course_info_str.find(" ", course_info_str.find(" ") + 1)
            #print("course code end is: ", course_code_end)
            next_word = course_info_str[course_info_str.rfind(" ") + 1: course_code_end]
            #print("next word is: ", next_word)
            
            if third_word in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]:
                # If the next word is a day, assume it's part of the course time, not the section
                time_start = words[2]
                index_first_letter = course_info_str.find(time_start)
                course_code = course_info_str[:course_code_end].strip().upper()
                course_time = course_info_str[index_first_letter:].strip()
                section = "0"  # No section provided
            else:
                # If the next word is not a day, assume it's the section information
                print("inside else")
                time_start = words[3]
                index_first_letter = course_info_str.find(time_start)
                print("time start is: ", time_start)
                print("index of first: ", index_first_letter)
                course_code = course_info_str[:course_code_end].strip().upper()
                course_time = course_info_str[index_first_letter:].strip()
                section = third_word
            
            # print("course code is: ", course_code)
            # print("course time is: ", course_time)
            # print("section is: ", section)
            
            total_info = {"course_code": course_code, "course_time": course_time, "section": section}
            await user_collection.update_one(
                {"username": current_user.username},
                {"$addToSet": {"recommendations": total_info}}
            )

    updated_user = await get_user(current_user.username, user_collection)
    #print("updated user is: ", updated_user)
    
    if updated_user:
        return {"message": "Recommendations info updated successfully", "success": True}
    else:
        return {"message": "Failed to update recommendations info", "success": False}



def get_hashed_password(password: str) -> str:
    return pwd_context.hash(password)

async def update_password(data: ChangePassword, current_user: UserInDB = Depends(get_current_user)):
    user = await get_user(current_user.username, user_collection)
    # Verify if the current password matches the one stored in the database
    if not verify_password(data.current_password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect current password")
    # Hash the new password
    new_hashed_password = pwd_context.hash(data.new_password)
    # Update user's password in the database
    await user_collection.update_one({"username": current_user.username}, {"$set": {"password": new_hashed_password}})
    updated_user = await get_user(current_user.username, user_collection)
    if updated_user.password == new_hashed_password:
        return {"message": "Password updated successfully",
                "success": True}
    else:
        return {"message": "Failed to update password",
                "success": False}


async def delete_user(userData : DeleteUser, token: HTTPAuthorizationCredentials):
    try:
        token_str = token.credentials  # Access the token string
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await user_collection.find_one({"username": username})
        if user:
            if not verify_password(userData.password, user["password"]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")
            await user_collection.delete_one({"username": username})
            return {"message": "User deleted successfully", "success": True}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except HTTPException as http_exc:
        # Catching HTTPException to ensure custom message is set
        return {"message": http_exc.detail, "success": False}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        # Catching any other exception to return the message
        return {"message": str(e), "success": False}



async def add_user_info(user_info: UserAddInfo, token: str):
    # Get the current user
    current_user = await get_current_user(token)
    
    # Construct the program collection name based on admission year and degree program
    program_collection_name = f"{user_info.degree_program.upper()}-{user_info.admission_year}"
    # Get the collection for the program and year
    program_collection = database.get_collection(program_collection_name)

    
    # Loop through the courses and update the user's entity based on course type
    for course_code in user_info.courses:
        # Modify the course_code

        modified_course_code = course_code.upper()  # Convert to uppercase
        modified_course_code = insert_space(modified_course_code)  # Insert space before the first digit
        # Find all occurrences of the modified course code in the program collection
        courses = program_collection.find({"course_code": modified_course_code})
        
        async for course in courses:
            if course:
                # Check the course type
                course_type = course.get("course_type")
                
                # Update the user's entity based on course type
                if course_type == "area":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"area_courses": modified_course_code}})
                elif course_type == "free":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"free_courses": modified_course_code}})
                elif course_type == "required":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"required_courses": modified_course_code}})
                elif course_type == "core":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"core_courses": modified_course_code}})
                elif course_type == "science_engineering":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"science_courses": modified_course_code}})
                elif course_type == "university":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"university_courses": modified_course_code}})

    # Update user's information
    user_collection.update_one({"username": current_user.username}, {"$set": {"degree_program": user_info.degree_program.upper()}})
    user_collection.update_one({"username": current_user.username}, {"$set": {"admission_year": user_info.admission_year}})
    user_collection.update_one({"username": current_user.username}, {"$set": {"double_major": "None" if user_info.double_major == "" else user_info.double_major}})
    user_collection.update_one({"username": current_user.username}, {"$set": {"minor": "None" if user_info.minor == "" else user_info.minor}})
    user_collection.update_one({"username": current_user.username}, {"$set": {"pdf_uploaded": True}})
    
    updated_user = await get_user(current_user.username, user_collection)
    
    if updated_user:
        return {"message": "User info updated successfully", "success": True}
    else:
        return {"message": "Failed to update user info", "success": False}

async def fetch_recommend_courses(token: str):
    try:
        user_info = await get_current_user_details(token)
        print("user info in fetch: ", user_info)
        pdf_info = user_info.pdf_uploaded
        print("user info is: ", user_info)
        
        if pdf_info == False:
            return {"message": "Not enough student information found", "success": False}
        else:
            degree_program = user_info.degree_program
            admission_year = user_info.admission_year
            program_collection_name = f"{degree_program.upper()}-{admission_year}"
            program_collection = database.get_collection(program_collection_name)
            prev_recommendations = user_info.recommendations
            
            def check_schedule_overlap(schedule1, schedule2):
                day1, *time_range1 = schedule1.split(" ")
                day2, *time_range2 = schedule2.split(" ")
                
                if day1 != day2:
                    return False
                
                time_range1 = " ".join(time_range1)
                time_range2 = " ".join(time_range2)
                
                start_time1, end_time1 = map(lambda x: datetime.datetime.strptime(x, "%a %H:%M-%H:%M"), time_range1.split("-"))
                start_time2, end_time2 = map(lambda x: datetime.datetime.strptime(x, "%a %H:%M-%H:%M"), time_range2.split("-"))
                
                return not (end_time1 <= start_time2 or end_time2 <= start_time1)
                        
            def course_already_taken(course_code, course_type):
                if course_type == "required":
                    return course_code in user_info.required_courses
                elif course_type == "area":
                    return course_code in user_info.area_courses
                elif course_type == "core":
                    return course_code in user_info.core_courses
            
            async def user_satisfies_prerequisites(course_code, prerequisites):
                for prerequisite in prerequisites:
                    if prerequisite not in user_info.core_courses and prerequisite not in user_info.required_courses and prerequisite not in user_info.area_courses:
                        return False
                return True
            
            async def recommend_courses():
                recommended_courses = []
                required_courses = await program_collection.find({"course_type": "required"}).to_list(length=None)
                area_courses = await program_collection.find({"course_type": "area"}).to_list(length=None)
                core_courses = await program_collection.find({"course_type": "core"}).to_list(length=None)

                course_types = {"required": required_courses, "area": area_courses, "core": core_courses}

                for course_type, courses in course_types.items():
                    for course in courses:
                        if not course_already_taken(course["course_code"], course["course_type"]):
                            if course["sections"]:
                                lecture_found = False
                                recitation_found = False
                                for section in course["sections"]:
                                    if section["times"]:
                                        schedule = section["times"][0][0]
                                        overlap = False
                                        for rec in prev_recommendations:
                                            for rec_course in rec:
                                                if check_schedule_overlap(schedule, rec_course[1]):
                                                    overlap = True
                                                    break
                                            if overlap:
                                                break
                                        if not overlap:
                                            if await user_satisfies_prerequisites(course["course_code"], course["condition"]["prerequisite"]):
                                                if section["section"] and section["section"][-1].isdigit():
                                                    if section["section"][-1] == '0':
                                                        section_section = section["section"]
                                                        if not lecture_found:
                                                            if section["section"]:
                                                                recommended_courses.append([course["course_code"], schedule, course["course_type"]])
                                                                lecture_found = True

                                                    else:
                                                        if not recitation_found:
                                                            section = course["course_code"] + " " + section["section"]
                                                            recommended_courses.append([section, schedule, "Recitation"])
                                                            recitation_found = True
                                                else:
                                                    section_section = section["section"]
                                                    if not any(char.isdigit() for char in section_section):
                                                        if not lecture_found:
                                                            if section["section"]:
                                                                recommended_courses.append([course["course_code"], schedule, course["course_type"]])
                                                                lecture_found = True
                return recommended_courses
            
            recommendations = await recommend_courses()
            
            top_courses_response = await fetch_top_courses(token)
            top_courses = {course["course_code"]: course["count"] for course in top_courses_response["top_courses"]}

            sorted_recommendations = sorted(recommendations, key=lambda course: top_courses.get(course[0], 0), reverse=True)
            
            top_5_recommendations = sorted_recommendations[:5]
            
            return {"recommendations": top_5_recommendations}
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def fetch_recommend_specific_courses(course: SpecificRecom, token: str):
    try:
        user_info = await get_current_user_details(token)
        pdf_info = user_info.pdf_uploaded
        formatted_courses = [insert_space(c) for c in course.selected_courses]
        course.selected_courses = formatted_courses
        
        if not pdf_info:
            return {"message": "Not enough student information found", "success": False}
        
        degree_program = user_info.degree_program
        admission_year = user_info.admission_year
        program_collection_name = f"{degree_program.upper()}-{admission_year}"
        program_collection = database.get_collection(program_collection_name)
        prev_recommendations = user_info.recommendations
        
        def check_schedule_overlap(schedule1, schedule2):
            day1, *time_range1 = schedule1.split(" ")
            day2, *time_range2 = schedule2.split(" ")
            
            if day1 != day2:
                return False
            
            time_range1 = " ".join(time_range1)
            time_range2 = " ".join(time_range2)
            
            start_time1, end_time1 = map(lambda x: datetime.strptime(x, "%H:%M"), time_range1.split("-"))
            start_time2, end_time2 = map(lambda x: datetime.strptime(x, "%H:%M"), time_range2.split("-"))
            
            return not (end_time1 <= start_time2 or end_time2 <= start_time1)
                        
        def course_already_taken(course_code, course_type):
            if course_type == "required":
                return course_code in user_info.required_courses
            elif course_type == "area":
                return course_code in user_info.area_courses
            elif course_type == "core":
                return course_code in user_info.core_courses
            return False
            
        async def user_satisfies_prerequisites(prerequisites):
            for prerequisite in prerequisites:
                if prerequisite not in user_info.core_courses and prerequisite not in user_info.required_courses and prerequisite not in user_info.area_courses:
                    return False
            return True
            
        async def recommend_courses(course_type, num_courses, recommended_courses):
            courses = await program_collection.find({"course_type": course_type}).to_list(length=None)
            count = 0
            for course in courses:
                if count >= num_courses:
                    break
                
                if not course_already_taken(course["course_code"], course["course_type"]):
                    if course["sections"]:
                        lecture_found = False
                        recitation_found = False
                        for section in course["sections"]:
                            if section["times"]:
                                schedule = section["times"][0][0]
                                overlap = False
                                for rec in prev_recommendations:
                                    for rec_course in rec:
                                        if check_schedule_overlap(schedule, rec_course[1]):
                                            overlap = True
                                            break
                                    if overlap:
                                        break
                                if not overlap:
                                    if await user_satisfies_prerequisites(course["condition"]["prerequisite"]):
                                        if section["section"] and section["section"][-1].isdigit():
                                            if section["section"][-1] == '0':
                                                if not lecture_found:
                                                    recommended_courses.append([course["course_code"], schedule, course["course_type"]])
                                                    lecture_found = True
                                                    count += 1
                                            else:
                                                if not recitation_found:
                                                    section_code = course["course_code"] + " " + section["section"]
                                                    recommended_courses.append([section_code, schedule, "Recitation"])
                                                    recitation_found = True
                                        else:
                                            if not any(char.isdigit() for char in section["section"]):
                                                if not lecture_found:
                                                    recommended_courses.append([course["course_code"], schedule, course["course_type"]])
                                                    lecture_found = True
                                                    count += 1
            return recommended_courses
        
        recommended_courses = []

        for selected_course_code in course.selected_courses:
            course_data = await program_collection.find_one({"course_code": selected_course_code})
            if course_data:
                if not course_already_taken(course_data["course_code"], course_data["course_type"]):
                    if await user_satisfies_prerequisites(course_data["condition"]["prerequisite"]):
                        if course_data["sections"]:
                            lecture_found = False
                            recitation_found = False
                            for section in course_data["sections"]:
                                if section["times"]:
                                    schedule = section["times"][0][0]
                                    overlap = False
                                    for rec in prev_recommendations:
                                        for rec_course in rec:
                                            if check_schedule_overlap(schedule, rec_course[1]):
                                                overlap = True
                                                break
                                        if overlap:
                                            break
                                    if not overlap:
                                        if section["section"] and section["section"][-1].isdigit():
                                            if section["section"][-1] == '0' and not lecture_found:
                                                recommended_courses.append([course_data["course_code"], schedule, course_data["course_type"]])
                                                lecture_found = True
                                        else:
                                            if not any(char.isdigit() for char in section["section"]):
                                                if not lecture_found:
                                                    recommended_courses.append([course_data["course_code"], schedule, course_data["course_type"]])
                                                    lecture_found = True
                                        if section["section"] and not section["section"][-1].isdigit() and not recitation_found:
                                            section_code = course_data["course_code"] + " " + section["section"]
                                            recommended_courses.append([section_code, schedule, "Recitation"])
                                            recitation_found = True
        
        recommended_courses = await recommend_courses("core", course.core, recommended_courses)
        recommended_courses = await recommend_courses("area", course.area, recommended_courses)
        recommended_courses = await recommend_courses("required", course.required, recommended_courses)
        recommended_courses = await recommend_courses("basic_science", course.basic_science, recommended_courses)
        recommended_courses = await recommend_courses("university", course.university, recommended_courses)
        recommended_courses = await recommend_courses("free", course.free, recommended_courses)
        
        return {"recommendations": recommended_courses}
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


 # BELOW CODE IS FOR CONTENT COLLABRATIVE FILTERING RECOMMENDATION
async def get_user_course_data(token: str):
    users_cursor = user_collection.find()
    users = []
    curr_user = await get_current_user_details(token)
    curr_major = curr_user.degree_program

    async for user in users_cursor:
        users.append(user)
        #print("USER IN GET: ", user)
    
    collection_names = await database.list_collection_names()

    course_collections = [name for name in collection_names if name.startswith(curr_major)]
    #print("COURSE COLLECTIONS ARE: ", course_collections)

    user_ids = [user["_id"] for user in users]
    #print("USER IDS ARE: ", user_ids)
    course_ids = []
    course_data = {}
    interactions = []

    for collection_name in course_collections:
        collection = database[collection_name]
        courses_cursor = collection.find()
        courses = []
        async for course in courses_cursor:
            courses.append(course)
            #print("COURSE IN GET: ", course)
        
        for course in courses:
            course_ids.append(course["course_code"])
            course_data[course["course_code"]] = course  # Store the course data for prerequisite checks

            #print("COURSE IDS ARE: ", course_ids)
        #print("course data is: ", course_data)
        for user in users:
            taken_courses = (user.get("required_courses", []) + 
                             user.get("science_courses", []) + 
                             user.get("university_courses", []) +
                             user.get("area_courses", []) + 
                             user.get("free_courses", []) + 
                             user.get("core_courses", []))
                             
            #print(f"User {user['_id']} taken courses: {taken_courses}")
            for course_id in taken_courses:
                #print("COURSE ID IS: ", course_id)
                if course_id in course_ids: 
                    interactions.append((user["_id"], course_id))
                    #print("INTERACTIONS ARE: ", interactions)
    
    
    return interactions, user_ids, course_ids, course_data

async def prepare_data(token: str):
    interactions, user_ids, course_ids, course_data = await get_user_course_data(token)
    
    if not interactions:
        raise ValueError("No interactions found.")

    user_encoder = LabelEncoder()
    course_encoder = LabelEncoder()

    user_encoder.fit(user_ids)
    course_encoder.fit(course_ids)

    user_ids_encoded = user_encoder.transform([x[0] for x in interactions])
    course_ids_encoded = course_encoder.transform([x[1] for x in interactions])

    num_users = len(user_encoder.classes_)
    num_courses = len(course_encoder.classes_)
    interaction_matrix = np.zeros((num_users, num_courses))

    for user, course in zip(user_ids_encoded, course_ids_encoded):
        interaction_matrix[user, course] = 1
    
    return interaction_matrix, user_encoder, course_encoder, course_data


def perform_svd(interaction_matrix, k=50):
    num_users, num_courses = interaction_matrix.shape
    k = min(k, num_users - 1, num_courses - 1)
    if k <= 0:
        raise ValueError("Invalid value for k. It must be greater than 0 and less than the minimum dimension of the matrix.")
        
    u, sigma, vt = svds(interaction_matrix, k=k)
    sigma = np.diag(sigma)
    predicted_ratings = np.dot(np.dot(u, sigma), vt)
    return predicted_ratings

def get_recommendations_for_user(user_id, predicted_ratings, user_encoder, course_encoder, course_data, taken_courses, num_recommendations=5):
    user_idx = user_encoder.transform([user_id])[0]
    user_ratings = predicted_ratings[user_idx]
    
    recommended_indices = np.argsort(user_ratings)[::-1]
    recommended_courses = course_encoder.inverse_transform(recommended_indices)

    def has_prerequisites(course_id):
        course = course_data[course_id]
        prerequisites = course.get("condition", {}).get("prerequisite", [])
        for prereq in prerequisites:
            if not all(prereq_course in taken_courses for prereq_course in prereq):
                return False
        return True

    filtered_recommendations = [course_id for course_id in recommended_courses if has_prerequisites(course_id)]
    
    return filtered_recommendations[:num_recommendations]


async def process_recommendation(token: HTTPAuthorizationCredentials):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

        user = await user_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Retrieve degree program and term from the user entity
        degree_program = user.get("degree_program")
        admission_year = user.get("admission_year")

        if not degree_program or not admission_year:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Degree program or admission year not found in user profile")

        try:
            interaction_matrix, user_encoder, course_encoder, course_data = await prepare_data(token)
        except ValueError as e:
            return {"recommendations": [], "success": False, "message": str(e)}

        if interaction_matrix.size == 0:
            return {"recommendations": [], "success": True}
        
        predicted_ratings = perform_svd(interaction_matrix)
        taken_courses = set(user.get("required_courses", []) + 
                            user.get("science_courses", []) + 
                            user.get("university_courses", []) +
                            user.get("area_courses", []) + 
                            user.get("free_courses", []) + 
                            user.get("core_courses", []))

        recommendations = get_recommendations_for_user(user["_id"], predicted_ratings, user_encoder, course_encoder, course_data, taken_courses)

        # Convert recommendations to a JSON-serializable format
        previous_recommendations = set(rec["course_code"] for rec in user.get("recommendations", []))

        filtered_recommendations = [course_id for course_id in recommendations 
                                    if course_id not in taken_courses and course_id not in previous_recommendations]

        return {"recommendations": filtered_recommendations, "success": True}

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})


# BELOW CODE IS FOR CONTENT BASED RECOMMENDATION
async def get_course_data(token: str):
    curr_user = await get_current_user_details(token)
    curr_major = curr_user.degree_program

    collection_names = await database.list_collection_names()
    course_collections = [name for name in collection_names if name.startswith(curr_major)]

    course_data = []

    for collection_name in course_collections:
        collection = database[collection_name]
        courses_cursor = collection.find()
        async for course in courses_cursor:
            course_data.append(course)
    
    return course_data


def extract_features(course):
    # Flatten the prerequisites list of lists into a single list of strings
    prerequisites = course.get("condition", {}).get("prerequisite", [])
    flat_prerequisites = [item for sublist in prerequisites for item in sublist]

    features = [
        course["course_type"],
        course["faculty_code"],
        " ".join(flat_prerequisites),  # Join the flattened list of prerequisites
        # Add more features as needed
    ]
    return " ".join(features)

async def prepare_user_profile(user, token):
    taken_courses = (user.get("required_courses", []) + 
                     user.get("science_courses", []) + 
                     user.get("university_courses", []) +
                     user.get("area_courses", []) + 
                     user.get("free_courses", []) + 
                     user.get("core_courses", []))
    
    user_profile = []
    curr_user = await get_current_user_details(token)
    for course_code in taken_courses:
        course = await database[curr_user.degree_program].find_one({"course_code": course_code})
        if course:
            user_profile.append(extract_features(course))
    
    return " ".join(user_profile)


async def content_based_recommendations(user, token: str, num_recommendations=5):
    course_data = await get_course_data(token)
    
    if not course_data:
        raise ValueError("No course data found.")

    user_profile = await prepare_user_profile(user, token)

    # Vectorize the course features
    tfidf_vectorizer = TfidfVectorizer()
    course_features = [extract_features(course) for course in course_data]
    tfidf_matrix = tfidf_vectorizer.fit_transform(course_features)

    # Vectorize the user profile
    user_tfidf = tfidf_vectorizer.transform([user_profile])

    # Compute cosine similarity between user profile and courses
    cosine_similarities = cosine_similarity(user_tfidf, tfidf_matrix).flatten()
    
    # Get top N recommendations
    similar_indices = cosine_similarities.argsort()[:-num_recommendations-1:-1]
    recommended_courses = [course_data[i]["course_code"] for i in similar_indices]

    # Filter out already taken and previously recommended courses
    taken_courses = set(user.get("required_courses", []) + 
                        user.get("science_courses", []) + 
                        user.get("university_courses", []) +
                        user.get("area_courses", []) + 
                        user.get("free_courses", []) + 
                        user.get("core_courses", []))
    
    previous_recommendations = set(rec["course_code"] for rec in user.get("recommendations", []))

    filtered_recommendations = [course_id for course_id in recommended_courses 
                                if course_id not in taken_courses and course_id not in previous_recommendations]

    return filtered_recommendations

async def process_content_recommendation(token: HTTPAuthorizationCredentials):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

        user = await user_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Retrieve degree program and term from the user entity
        degree_program = user.get("degree_program")
        admission_year = user.get("admission_year")

        if not degree_program or not admission_year:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Degree program or admission year not found in user profile")

        try:
            recommendations = await content_based_recommendations(user, token)
        except ValueError as e:
            return {"recommendations": [], "success": False, "message": str(e)}

        return {"recommendations": recommendations, "success": True}

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})
    


async def fetch_top_courses(token: str):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

        user = await user_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Retrieve degree program and term from the user entity
        users_cursor = user_collection.find()
        users = []
        async for user in users_cursor:
            users.append(user)
        
        all_courses = []
        for user in users:
            all_courses.extend(user.get("required_courses", []))
            all_courses.extend(user.get("science_courses", []))
            all_courses.extend(user.get("university_courses", []))
            all_courses.extend(user.get("area_courses", []))
            all_courses.extend(user.get("free_courses", []))
            all_courses.extend(user.get("core_courses", []))

        if not all_courses:
            return {"top_courses": [], "success": True, "message": "No courses found"}

        # Count course frequencies
        course_counts = Counter(all_courses)
        top_courses = course_counts.most_common(3)

        # Prepare the response
        top_courses_list = [{"course_code": course, "count": count} for course, count in top_courses]

        return {"top_courses": top_courses_list, "success": True}

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})


async def fetch_least_courses(token: HTTPAuthorizationCredentials):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

        user = await user_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Retrieve all users
        users_cursor = user_collection.find()
        users = []
        async for user in users_cursor:
            users.append(user)
        
        all_courses = []
        for user in users:
            all_courses.extend(user.get("required_courses", []))
            all_courses.extend(user.get("science_courses", []))
            all_courses.extend(user.get("university_courses", []))
            all_courses.extend(user.get("area_courses", []))
            all_courses.extend(user.get("free_courses", []))
            all_courses.extend(user.get("core_courses", []))

        if not all_courses:
            return {"least_courses": [], "success": True, "message": "No courses found"}

        # Count course frequencies
        course_counts = Counter(all_courses)
        most_common_courses = course_counts.most_common(3)
        least_common_courses = course_counts.most_common()[:-4:-1]  # Get the least common 3 courses

        # Get counts of the most common courses
        most_common_counts = {course: count for course, count in most_common_courses}

        # Filter out least common courses that have the same count as any of the most common courses
        filtered_least_courses = [
            (course, count) for course, count in least_common_courses
            if count not in most_common_counts.values()
        ]

        # Ensure we get exactly 3 courses in the result
        filtered_least_courses = filtered_least_courses[:3]

        # Prepare the response
        least_courses_list = [{"course_code": course, "count": count} for course, count in filtered_least_courses]

        return {"least_courses": least_courses_list, "success": True}

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token", headers={"WWW-Authenticate": "Bearer"})

async def add_course_info_user(course_info : CourseAdd, token: str):
    current_user = await get_current_user_details(token)
    # Construct the program collection name based on admission year and degree program
    program_collection_name = f"{current_user.degree_program.upper()}-{current_user.admission_year}"
    # Get the collection for the program and year
    program_collection = database.get_collection(program_collection_name)

    
    # Loop through the courses and update the user's entity based on course type
    for course_code in course_info.courses:
        # Modify the course_code

        modified_course_code = course_code.upper()  # Convert to uppercase
        modified_course_code = insert_space(modified_course_code)  # Insert space before the first digit
        # Find all occurrences of the modified course code in the program collection
        courses = program_collection.find({"course_code": modified_course_code})
        
        async for course in courses:
            if course:
                # Check the course type
                course_type = course.get("course_type")
                
                # Update the user's entity based on course type
                if course_type == "area":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"area_courses": modified_course_code}})
                elif course_type == "free":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"free_courses": modified_course_code}})
                elif course_type == "required":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"required_courses": modified_course_code}})
                elif course_type == "core":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"core_courses": modified_course_code}})
                elif course_type == "science_engineering":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"science_courses": modified_course_code}})
                elif course_type == "university":
                    await user_collection.update_one({"username": current_user.username}, {"$addToSet": {"university_courses": modified_course_code}})
    
    updated_user = await get_user(current_user.username, user_collection)
    
    if updated_user:
        return {"message": "Course info updated successfully", "success": True}
    else:
        return {"message": "Failed to update course info", "success": False}