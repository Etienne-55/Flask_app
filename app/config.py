from datetime import timedelta

class Config:
    SECRET_KEY = 'your-secret-key' 
    SQLALCHEMY_DATABASE_URI = 'mysql://user:password@localhost/database'  
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = "jwt-secret-key"  
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    SWAGGER_UI_DOC_EXPANSION = 'list' 
    SWAGGER_UI_JSONEDITOR = True
    SWAGGER_UI_OPERATION_ID = True
    SWAGGER_UI_REQUEST_DURATION = True
    RESTX_MASK_SWAGGER = False  
    SWAGGER_UI_LANGUAGES = ['en']
    SWAGGER_UI_OAUTH_CLIENT_ID = None
    SWAGGER_UI_OAUTH_REALM = None
    SWAGGER_UI_OAUTH_APP_NAME = None