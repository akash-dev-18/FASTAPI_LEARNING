# --- IMPORTS ---
import uvicorn
from fastapi import (
    FastAPI, Path, Query, Body, Cookie, Header, Form, File, UploadFile, 
    Depends, HTTPException, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import Optional, List, Set, Dict, Union
from typing_extensions import Annotated

# Security (JWT) Imports
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

# SQL (SQLAlchemy) Imports
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# MongoDB (Motor) Imports
import motor.motor_asyncio
from bson import ObjectId

# --- 1. SETUP & CONFIGURATION ---

# App & Middleware (CORS)
app = FastAPI()
app.add_middleware(
    CORSMiddleWARE,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# Security (JWT) Config
SECRET_KEY = "Y_E_H_K_O_I_S_T_R_O_N_G_K_E_Y_H_A_I" # Real app me isko securely store karna
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # "token" endpoint ka naam hai

# SQL (SQLAlchemy) Config
DATABASE_URL = "sqlite:///./test.db" # Example: SQLite
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# MongoDB (Motor) Config
MONGO_URL = "mongodb://localhost:27017" # Local MongoDB
mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
db = mongo_client.fastapi_db # Database ka naam


# --- 2. DATABASE MODELS ---

# SQL (SQLAlchemy) Model
class SqlItem(Base):
    __tablename__ = "sql_items"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    price = Column(Float)

# Pydantic Models (Validation & Response)
class ItemBase(BaseModel):
    name: str = Field(..., min_length=3)
    price: float = Field(..., gt=0)

class ItemCreate(ItemBase):
    pass

class ItemPublic(ItemBase):
    id: int # SQL ke liye
    
    class Config:
        orm_mode = True # SQLAlchemy object se direct convert karne ke liye

# MongoDB Pydantic Model (ID alag se handle hota hai)
class MongoItem(ItemBase):
    id: str = Field(..., alias="_id") # Mongo ka '_id' ko 'id' me map karega
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str} # ObjectId ko str me convert karega

# Security Pydantic Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


# Create SQL Database (Sirf first run ke liye)
Base.metadata.create_all(bind=engine)


# --- 3. DEPENDENCIES (DI) ---

# SQL Database Session Dependency
def get_db():
    db_session = SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()

# SQL DB Dependency (Annotated)
DbDep = Annotated[Session, Depends(get_db)]

# Security: Password Hashing
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Security: Create JWT Token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Security: Get Current User (Yeh main dependency hai)
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    # Yahan real app me DB se user fetch karoge
    # user = get_user_from_db(username=token_data.username)
    user = {"username": token_data.username} # Abhi ke liye stub
    if user is None:
        raise credentials_exception
    return user

# Current User Dependency (Annotated)
UserDep = Annotated[dict, Depends(get_current_user)]


# --- 4. ENDPOINTS ---

# --- Security (OAuth2 / JWT) Endpoints ---

@app.post("/token", response_model=Token, tags=["Security"])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    # Real app me DB se user check karoge
    # Hashed password: get_password_hash("pass123")
    hashed_pass = "$2b$12$Eix6bDMjZ7e39f7wG2.Gsu0k3.G2sN2Qk.vR.xP.E.2sO.S.2v/bK"
    
    is_user = (form_data.username == "admin")
    is_pass = verify_password(form_data.password, hashed_pass)

    if not (is_user and is_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", tags=["Security"])
async def read_users_me(current_user: UserDep):
    # Agar token valid nahi hoga toh 'get_current_user' 401 Error dega
    return {"message": "Hello, this is a protected route!", "user": current_user}


# --- SQL (SQLAlchemy) Endpoints ---

@app.post("/sql-items/", response_model=ItemPublic, tags=["SQL"])
async def create_sql_item(item: ItemCreate, db: DbDep):
    # Pydantic model ko SQLAlchemy model me convert kiya
    db_item = SqlItem(name=item.name, price=item.price)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

@app.get("/sql-items/{item_id}", response_model=ItemPublic, tags=["SQL"])
async def read_sql_item(item_id: int, db: DbDep):
    db_item = db.query(SqlItem).filter(SqlItem.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


# --- MongoDB (Motor) Endpoints ---

@app.post("/mongo-items/", response_model=MongoItem, tags=["MongoDB"])
async def create_mongo_item(item: ItemCreate):
    item_dict = item.dict()
    # 'db' object (line 44 se) use ho raha hai
    result = await db.mongo_items.insert_one(item_dict)
    
    # Inserted item ko wapas fetch karna
    created_item = await db.mongo_items.find_one({"_id": result.inserted_id})
    return created_item


@app.get("/mongo-items/{item_id}", response_model=MongoItem, tags=["MongoDB"])
async def read_mongo_item(item_id: str):
    try:
        # Mongo ke liye ID ko 'ObjectId' me convert karna zaroori hai
        obj_id = ObjectId(item_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid MongoDB ObjectId")
        
    item = await db.mongo_items.find_one({"_id": obj_id})
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


# --- 5. RUN THE APP ---
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
