# Dashboard admin credentials
import os

admins = [
    {
        "username": i.split(":")[0],
        "password": i.split(":")[1]
    }
    for i in os.getenv("ADMIN_USERS").split(",")
]

# Used in communication of slave and master
slave_token = os.getenv("SLAVE_TOKEN")

# Used to create access token
SECRET_KEY = os.getenv("MASTER_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 600
