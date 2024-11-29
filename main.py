from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
import pymysql

# Secret key to encode/decode JWT
SECRET_KEY = "b3c99c0abefb83e2d1f5a707f320d35072c741e5f4f1494d3a9f0f7f35e8f40c"  # Example secret key (change this for production)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# MySQL Database Configuration
DB_HOST = "db.instance.local"  # Update with your DB instance private IP
DB_USER = "db_user"       # Update with your specific user
DB_PASSWORD = "Changeme123@"   # Update with your user's password
DB_NAME = "test_db"

# Dummy user data (for authentication)
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "API test user",
        "email": "testuser@example.com",
        "hashed_password": "Changeme123@",  # Plain-text for demo, use hashing in production
    }
}
# Function to authenticate user
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if user and password == user["hashed_password"]:
        return user
    return None

# Function to create a JWT access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = 
None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))    
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dependency to verify the token
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
# Route to get a token
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

class Item(BaseModel):
    name: str
    price: float
    quantity: int
    description: Optional[str] = None

# CRUD operations on 'items' table
@app.get("/items/")
def read_items(current_user: str = Depends(get_current_user)):
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM items")  # Select all rows from the 'items' table
        items = cursor.fetchall()  # Fetch all results
    conn.close()
    if not items:
        raise HTTPException(status_code=404, detail="No items found")
    return {"items": items}
@app.post("/items/")
def create_item(item: Item, current_user: str = Depends(get_current_user)):
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO items (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
            (item.name, item.description, item.price, item.quantity)
        )
        conn.commit()
    conn.close()
    return {"message": "Item created successfully"}

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item, current_user: str = Depends(get_current_user)):
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    with conn.cursor() as cursor:
        cursor.execute("""
            UPDATE items 
            SET name = %s, description = %s, price = %s, quantity = %s 
            WHERE id = %s
        """, (item.name, item.description, item.price, item.quantity, item_id))
        conn.commit()
    conn.close()
    return {"message": "Item updated successfully"}
@app.delete("/items/{item_id}")
def delete_item(item_id: int, current_user: str = Depends(get_current_user)):
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM items WHERE id = %s", (item_id,))
        conn.commit()
    conn.close()
    return {"message": "Item deleted successfully"}