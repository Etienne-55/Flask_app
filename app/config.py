from datetime import timedelta

class Config:
    SECRET_KEY = 'your-secret-key' 
    SQLALCHEMY_DATABASE_URI = 'mysql://user:password@localhost/db_name'  
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = "jwt-secret-key"  
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)