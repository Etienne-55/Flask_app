from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_restx import Api
from app.config import Config

db = SQLAlchemy()
jwt = JWTManager()
api = Api(
    title='Blog API',
    version='1.0',
    description='A simple blog API with user authentication',
    doc='/docs'  
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)
    api.init_app(app)

    from app.routes import auth_ns, posts_ns, users_ns
    api.add_namespace(auth_ns)
    api.add_namespace(posts_ns)
    api.add_namespace(users_ns)

    with app.app_context():
        db.create_all()

    return app