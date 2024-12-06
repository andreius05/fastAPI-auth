from fastapi import FastAPI, HTTPException,Request
from fastapi import Depends
from sqlmodel import Field, Session, SQLModel, create_engine,select
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Annotated
from contextlib import asynccontextmanager
import jwt
from jwt_utilits import jwt_required,create_access_token,verify_token,get_identity_from_token
from typing import Optional


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(lifespan=lambda app: lifespan(app))

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

class User(SQLModel, table=True):
    __tablename__ = "user"
    id: int = Field(primary_key=True, nullable=False)
    username: str = Field(unique=True, index=True, nullable=False)
    email: str = Field(unique=True, nullable=False)
    password: str = Field(nullable=False)

    __table_args__ = {"extend_existing": True}

class Register(BaseModel):
    username: str
    email: str
    password: str


class Login(BaseModel):
    username:str
    email:str
    password:str

sqlite_file_name = "tables.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine, checkfirst=True)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield
    # Clean-up actions (if any) can be placed here

@app.post("/register")
async def register(register: Register, session: SessionDep):
    user_ex = session.query(User).filter(User.email == register.email).first()
    if user_ex:
        raise HTTPException(status_code=409, detail="This user already exists")
        
    hs_password = hash_password(register.password)
    user = User(username=register.username, email=register.email, password=hs_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": f"User created with id: {user.id}, username: {user.username}"}


@app.post("/login")
async def login(logining:Login, session: SessionDep):
    user = session.query(User).filter((User.email == logining.email) | (User.username == logining.username)).first()

    if not user:
        return HTTPException(status_code=409,detail="No users with this email or username")
    
    if verify_password(logining.password,user.password):
        data = {"sub": user.username, "id": user.id}  # Example data: including username and user ID
        access_token=create_access_token(identity=user.id,data=data)
        return {"status":"OK","access_token":access_token}

@app.get("/")
async def home():
    return {"message": "Hello world"}



@app.get("/@me/{user_id}")
@jwt_required
async def me(request:Request,user_id: int, session: SessionDep,current_user = None):
    user = session.get(User,user_id)
    if not user:
        return HTTPException(status_code = 409,detail ="User is already exist")
    return {
        "message":"Here is your account info",
        "id":user.id,
        "username":user.username,
        "email":user.email,
        "password":user.password
    }

@app.get("/users")
@jwt_required
async def get_users(request:Request,session: SessionDep,offset: int = 0, limit: int = 10,current_user: str = None):
    users = session.exec(select(User).offset(offset).limit(limit)).all()
    return {"This is all users":users}

    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", reload=True)
