# write a simple blog api that allows users to create, read, update, and delete blog posts.
# use fastapi, sqlalchemy, and sqlite.
# create a blog post model with the following fields:
# - id
# - title
# - content
# - published
# - author
# create the following endpoints:
# - GET /posts
# - GET /posts/{id}
# - POST /posts
# - PUT /posts/{id}
# - DELETE /posts/{id}
# add a regitered user field to the blog post model.
# add a login endpoint that returns a jwt token.
# add a user model with the following fields:
# - id
# - username
# - password
# - email
# - registered
# - posts
# create the following endpoints:
# - POST /register
# - POST /login
# - GET /users
# - GET /users/{id}
# - PUT /users/{id}
# - DELETE /users/{id}
# the user model should be stored in an sqlite database.
# the blog post model should be stored in an sqlite database.
# the database should be created and initialized when the application starts.
# the database should be closed when the application stops.
# the database should be accessed using sqlalchemy.
# users should be able to register and login using the api.
# users should be able to create, read blog posts if they are logged in.
# users should only be able to update and delete their own blog posts if they are logged in.
# users should be able to view all blog posts no matter if they are logged in or not.
# users should be able to view all users if they are logged in.
# users should only be able to update and delete their own user if they are logged in.
# the application should be able to run using uvicorn.

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, relationship
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from typing import List, Optional
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from fastapi.responses import JSONResponse

# create the database
DATABASE_URL = "sqlite:///./blog.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# SQLAlchemy ORM Models
class UserData(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    registered = Column(DateTime, default=datetime.utcnow)
    posts = relationship("PostData", back_populates="author")

class PostData(Base):
    __tablename__ = 'posts'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String)
    content = Column(String)
    published = Column(DateTime, default=datetime.utcnow)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("UserData", back_populates="posts")

# Pydantic Models
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class User(UserCreate):
    id: Optional[int] = None
    registered: datetime
    posts: List['Post'] = []

    class Config:
        from_attributes = True

class PostBase(BaseModel):
    title: str
    content: str

class PostCreate(PostBase):
    pass

class Post(PostCreate):
    id: int
    published: datetime
    author_id: int

    class Config:
        from_attributes = True



# create the security

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class TokenData(BaseModel):
    username: str = None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# create the functions

def get_user(db: Session, user_id: int):
    return db.query(UserData).filter(UserData.id == user_id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(UserData).filter(UserData.email == email).first()

def get_user_by_username(db: Session, username: str):
    return db.query(UserData).filter(UserData.username == username).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(UserData).offset(skip).limit(limit).all()


def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = UserData(username=user.username, email=user.email, password=hashed_password, registered=datetime.utcnow())
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except Exception as e:
        db.rollback()
        print(f"Error occurred: {e}")
        raise HTTPException(status_code=400, detail="An error occurred while creating the user.")
    return db_user
def create_post(db: Session, post: PostCreate, user_id: int):
    db_post = PostData(**post.dict(), author_id=user_id)
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post

def get_posts(db: Session, skip: int = 0, limit: int = 100):
    return db.query(PostData).offset(skip).limit(limit).all()

def get_post(db: Session, post_id: int):
    return db.query(PostData).filter(PostData.id == post_id).first()

def update_post(db: Session, post_id: int, post: PostCreate):
    db_post = db.query(PostData).filter(PostData.id == post_id).first()
    db_post.title = post.title
    db_post.content = post.content
    db.commit()
    db.refresh(db_post)
    return db_post

def delete_post(db: Session, post_id: int):
    db_post = db.query(PostData).filter(Post.id == post_id).first()
    db.delete(db_post)
    db.commit()
    return db_post

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not pwd_context.verify(password, user.password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=2)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# create the app
app = FastAPI()

@app.post("/register", response_model=User)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db, user)

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@app.get("/users", response_model=List[User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != 1:
        raise HTTPException(status_code=403, detail="Forbidden")
    return get_users(db, skip=skip, limit=limit)

@app.get("/users/{user_id}", response_model=User)
#def read_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
def read_user(user_id: int, db: Session = Depends(get_db)):
    #if current_user.id != user_id:
    #    raise HTTPException(status_code=403, detail="Forbidden")
    db_user = get_user(db, user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db_user.password = ""
    return db_user

@app.put("/users/{user_id}", response_model=User)
def update_user(user_id: int, user: UserCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    db_user = get_user(db, user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db_user.username = user.username
    db_user.email = user.email
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}", response_model=User)
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    db_user = get_user(db, user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return db_user

@app.get("/posts", response_model=List[Post])
def read_posts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_posts(db, skip=skip, limit=limit)

@app.get("/posts/{post_id}", response_model=Post)
def read_post(post_id: int, db: Session = Depends(get_db)):
    db_post = get_post(db, post_id)
    if db_post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return db_post

@app.post("/posts", response_model=Post)
def create_post_route(post: PostCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return create_post(db, post, user_id=current_user.id)

@app.put("/posts/{post_id}", response_model=Post)
def update_post_route(post_id: int, post: PostCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_post = get_post(db, post_id)
    if db_post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if current_user.id != db_post.author_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    return update_post(db, post_id, post)

@app.delete("/posts/{post_id}", response_model=Post)
def delete_post_route(post_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_post = get_post(db, post_id)
    if db_post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if current_user.id != db_post.author_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    return delete_post(db, post_id)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

@app.on_event("shutdown")
def shutdown():
    engine.dispose()

if __name__ == "__main__":
    import uvicorn
    #print(SECRET_KEY)
    uvicorn.run(app, host="0.0.0.0", port=8000)

# run the app
# uvicorn main:app --reload