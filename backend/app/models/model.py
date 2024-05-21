from pydantic import BaseModel 
from pymongo import MongoClient
from bson import ObjectId
from typing import List  # Import List from the typing module
from typing import Optional  # Import Optional from the typing module
from pydantic import Field
from pydantic.networks import EmailStr
from typing import Dict, Any


class CourseTime(BaseModel):    
    section: Optional[str]
    time : Optional[str]


class Prerequisite(BaseModel):
    prerequisite : List[str]
    general : List[str]


class Course(BaseModel):
    _id: ObjectId
    course_code: str
    course_type: str
    course_name : str
    ects_credits : int 
    su_credits : int
    faculty_code : str
    condition : Prerequisite
    course_time: List[Dict[str, Any]] = []



class ScienceCourse(BaseModel):
    _id: ObjectId
    course_code: str
    course_type: str
    course_name : str
    engineering_credits : int 
    science_credits : int
    faculty_code : str
    course_time : List[CourseTime]


class CourseRecommendation(BaseModel):
    course_code: str
    

class UserRegistration(BaseModel):
    username : str =Field(min_length=3)
    password : str = Field(min_length=4)
    email : EmailStr 
    first_name : str
    last_name : str

    def model_dump(self):
        return self.dict()



class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str 

class User(BaseModel):
    username : str =Field(min_length=3)
    password : str = Field(min_length=4)
    email : EmailStr 
    first_name : str
    last_name : str

class UserDetails(BaseModel):
    _id: ObjectId
    username : str
    email : EmailStr
    first_name : str
    last_name : str
    admission_year: int
    degree_program : str
    double_major: Optional[str]
    minor: Optional[str]
    area_courses : List[str]
    core_courses : List[str]
    free_courses : List[str]
    science_courses : List[str]
    university_courses : List[str]
    required_courses : List[str]
    pdf_uploaded : bool
    recommendations : List[dict]

class UserInDB(User):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ChangePassword(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


class UserAddInfo(BaseModel):
    courses: List[str]
    admission_year: int
    degree_program : str
    double_major: Optional[str]
    minor: Optional[str]


class CourseAdd(BaseModel):
    courses : List[str]


class CourseRecommendation(BaseModel):
    selected_courses: List[str]
    core: int
    area : int 
    required : int 
    basic_science : int 
    university : int


class AddPrevRecoom(BaseModel):
    courses: List[List[str]]


class UserGetAllResponse(BaseModel):
    username: str
    first_name: str
    last_name: str
    degree_program: str
    double_major: Optional[str]
    minor: Optional[str]
    pdf_uploaded: bool
    admission_year: int
    recommendations: List[dict]