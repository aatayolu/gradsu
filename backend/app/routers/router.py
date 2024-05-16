from models.model import Course
from models.model import CourseRecommendation
from models.model import ScienceCourse, UserRegistration, User, UserInDB, ChangePassword, UserAddInfo, UserDetails, AddPrevRecoom, UserGetAllResponse
from typing import List  # Import List from the typing module
from fastapi import APIRouter
from config.database import cs_2018_fall
from config.database import user_collection, get_program_collection
from bson import ObjectId #this is what mongodb uses to be able to identify the id that it creates itself
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, HTTPAuthorizationCredentials, HTTPBearer
from config.database import database
from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta
from fastapi import Body
import re
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
    user = await get_user(username, user_collection)
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
        print("USER IS: ", user)
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
        print("USER IS: ", user)
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
    print("current user is: ", current_user)
    
    for course_list in courses.courses:  # Iterate over each list of courses
        for course_info_str in course_list:  # Iterate over each course info string in the list
            section = "0"  # Initialize section variable before processing each course
            
            course_info_str = course_info_str.strip()  # Extract the course info string
            print("course info str is: ", course_info_str)
            words = course_info_str.split()
            third_word = words[2]
            print("third word is: ", third_word)
            
            
            # Check if there's a day immediately after the space after the course code
            course_code_end = course_info_str.find(" ", course_info_str.find(" ") + 1)
            print("course code end is: ", course_code_end)
            next_word = course_info_str[course_info_str.rfind(" ") + 1: course_code_end]
            print("next word is: ", next_word)
            
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
            
            print("course code is: ", course_code)
            print("course time is: ", course_time)
            print("section is: ", section)
            
            total_info = {"course_code": course_code, "course_time": course_time, "section": section}
            await user_collection.update_one(
                {"username": current_user.username},
                {"$addToSet": {"recommendations": total_info}}
            )

    updated_user = await get_user(current_user.username, user_collection)
    print("updated user is: ", updated_user)
    
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


async def delete_user(token: HTTPAuthorizationCredentials):
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
            await user_collection.delete_one({"username": username})
            return {"message": "User deleted successfully", "success": True}
    except JWTError:
        return {"message": "Invalid token", "success": False}
    except Exception as e:
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
            
            # Function to check if two schedules overlap
            def check_schedule_overlap(schedule1, schedule2):
                # Extract day and time ranges from the schedule strings
                day1, *time_range1 = schedule1.split(" ")
                day2, *time_range2 = schedule2.split(" ")
                
                # If the days are different, no overlap
                if day1 != day2:
                    return False
                
                # Join any additional values in the time range strings
                time_range1 = " ".join(time_range1)
                time_range2 = " ".join(time_range2)
                
                # Parse time ranges
                start_time1, end_time1 = map(lambda x: datetime.strptime(x, "%a %H:%M-%H:%M"), time_range1.split("-"))
                start_time2, end_time2 = map(lambda x: datetime.strptime(x, "%a %H:%M-%H:%M"), time_range2.split("-"))
                
                # Check for overlap
                return not (end_time1 <= start_time2 or end_time2 <= start_time1)
                        
            # Function to check if a course is already taken by the user
            def course_already_taken(course_code, course_type):
                if course_type == "university":
                    return course_code in user_info.university_courses
                # Add more checks for other course types if needed
            
            # Function to check if user satisfies prerequisites for a course
            async def user_satisfies_prerequisites(course_code, prerequisites):
                for prerequisite in prerequisites:
                    if prerequisite not in user_info.core_courses and prerequisite not in user_info.required_courses:
                        return False
                return True
            
            # Function to recommend courses
            async def recommend_courses():
                recommended_courses = []
                # Fetch all courses from the university collection
                university_courses = await program_collection.find({"course_type": "university"}).to_list(length=None)
                for course in university_courses:
                    # Check if the course is not already taken
                    if not course_already_taken(course["course_code"], course["course_type"]):
                        # Check if the course is open in the current semester
                        if course["sections"]:
                            lecture_found = False
                            recitation_found = False
                            for section in course["sections"]:
                                # Check if the section has times
                                
                                if section["times"]:
                                    schedule = section["times"][0][0]  # Considering only the first time slot
                                    # Check if the schedule overlaps with any previous recommendations
                                    overlap = False
                                    for rec in prev_recommendations:
                                        for rec_course in rec:
                                            if check_schedule_overlap(schedule, rec_course[1]):
                                                overlap = True
                                                break
                                        if overlap:
                                            break
                                    if not overlap:
                                        # Check if the user satisfies prerequisites for the course
                                        if await user_satisfies_prerequisites(course["course_code"], course["condition"]["prerequisite"]):
                                            if section["section"] and section["section"][-1].isdigit():
                                                # This is a recitation section
                                                if not recitation_found:
                                                    section = course["course_code"] + " " + section["section"]
                                                    recommended_courses.append([section, schedule, "Recitation"])
                                                    recitation_found = True  # Set recitation found to True after finding a recitation
                                            else:
                                                # This is a lecture section
                                                section_section = section["section"]
                                                if not any(char.isdigit() for char in section_section):
                                                    print("LECTURE IS: ", section["section"])
                                                    if not lecture_found:
                                                        
                                                        print("LECTURE IS: ", section["section"])
                                                        if section["section"] :
                                                                recommended_courses.append([course["course_code"], schedule, "Required"])
                                                                lecture_found = True
                        # else:  # If there are no sections at all, consider the course as a whole
                        #     if await user_satisfies_prerequisites(course["course_code"], course["condition"]["prerequisite"]):
                        #         recommended_courses.append([course["course_code"], "", "Required"])  # No schedule for courses without sections
                return recommended_courses
            
            # Recommend courses
            recommendations = await recommend_courses()
            
            # Return the recommendations
            return {"recommendations": recommendations}
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

