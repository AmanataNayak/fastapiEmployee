from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status,UploadFile,File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from bson import ObjectId
from jose import jwt,JWTError
import os 
from fastapi.staticfiles import StaticFiles
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import timedelta,datetime,timezone
from jose import jwt

app = FastAPI()

oauth_scheme = OAuth2PasswordBearer(tokenUrl='/login')
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_FOLDER = 'uploads'
app.mount('/uploads',StaticFiles(directory=UPLOAD_FOLDER),name=UPLOAD_FOLDER)

mongodb_url = 'mongodb://localhost:27017'
client = AsyncIOMotorClient(mongodb_url)
db = client['Security']
user_collection = db['User']
employee_collection = db['employee']

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


class User(BaseModel):
    name: str
    email: str
    password: str

class Employee(BaseModel):
    name:str
    position:str
    salary:int
    age:int 
    image: str=None

class Token(BaseModel):
    access_token : str
    token_type : str


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def hash_pass(password):
    return pwd_context.hash(password)


def verify_pass(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate(user,password):
    if not user:
        return False
    
    if not verify_pass(password,user['password']):
        return False
    
    return user

def create_access_token(data:dict,expires:timedelta | None):
    to_encode = data.copy()
    if expires:
        expire = datetime.now(timezone.utc) + expires
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({'exp':expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt
    
async def get_current_user(token:str = Depends(oauth_scheme)):
    credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username = payload.get('sub')
        if username is None:
            raise credentials
    except JWTError:
        raise credentials
    user = await user_collection.find_one({'name':username})

    if user is None:
        raise credentials
    
    return user


@app.post('/register')
async def register(u: User) -> User:
    u.password = hash_pass(u.password)
    await user_collection.insert_one(u.dict())
    return u


@app.post('/login')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_doc = await user_collection.find_one({'name': form_data.username})
    user = authenticate(user_doc,form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={'sub':user['name']},expires=access_token_expires
    )

    return Token(access_token=access_token,token_type='bearer')


@app.post('/')
async def create(image:Annotated[UploadFile,File()],employee:Annotated[Employee,Depends()],current_user:User= Depends(get_current_user)):
    try:
        if image:
            file_path = os.path.join(UPLOAD_FOLDER, image.filename)
            with open(file_path, 'wb') as f:
                f.write(await image.read())
            employee.image = file_path  

        result = await employee_collection.insert_one(employee.dict())
        return {'msg': 'Employee created successfully', 'employee_id': str(result.inserted_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to create employee")


@app.get("/")
async def read():
    data = employee_collection.find()
    employees = []
    async for employee in data:
        employee['_id'] = str(employee['_id'])
        employees.append(employee)
    return employees



@app.patch('/{id}')
async def update(id:str,image:Annotated[UploadFile,File()],employee:Annotated[Employee,Depends()],current_user:User= Depends(get_current_user)):
    try:
        if image:
            file_path = os.path.join(UPLOAD_FOLDER, image.filename)
            with open(file_path, 'wb') as f:
                f.write(await image.read())
            employee.image = file_path  
        result = await employee_collection.find_one_and_update({'_id': ObjectId(id)}, {'$set': employee.dict()})

        if result:
            image_path = result.get('image')
            if image_path and os.path.exists(image_path):
                os.remove(image_path)
            return {'msg': 'Employee updated successfully'}
        else:
            raise HTTPException(status_code=404, detail="Employee not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to update employee")



@app.delete('/{id}')
async def delete(id:str,current_user:User= Depends(get_current_user)):
    employee_data = await employee_collection.find_one_and_delete({'_id': ObjectId(id)})
    if employee_data:
        image_path = employee_data.get('image')
        if image_path and os.path.exists(image_path):
            os.remove(image_path)
        return {'msg': 'Employee deleted successfully'}
    else:
        raise HTTPException(status_code=404, detail="Employee not found")