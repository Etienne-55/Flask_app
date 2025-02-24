from flask_restx import Namespace, Resource, fields
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models import User, Post
from app import db, api

auth_ns = Namespace('auth', description='Authentication operations')
posts_ns = Namespace('posts', description='Post operations')
users_ns = Namespace('users', description='User operations')

user_model = api.model('User', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password'),
})

post_model = api.model('Post', {
    'content': fields.String(required=True, description='Post content')
})

post_response = api.model('PostResponse', {
    'id': fields.Integer(description='Post ID'),
    'content': fields.String(description='Post content'),
    'created_at': fields.DateTime(description='Creation timestamp'),
    'author_email': fields.String(description='Author email'),
    'user_id': fields.Integer(description='User ID'),
    'is_owner': fields.Boolean(description='Whether current user owns the post')
})

user_response = api.model('UserResponse', {
    'id': fields.Integer(description='User ID'),
    'email': fields.String(description='User email'),
    'is_admin': fields.Boolean(description='Whether the user is an admin'),
    'post_count': fields.Integer(description='Number of posts by the user')
})

user_update_model = api.model('UserUpdate', {
    'email': fields.String(required=False, description='New email'),
    'password': fields.String(required=False, description='New password')
})

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(user_model)
    @auth_ns.doc(responses={201: 'Success', 400: 'Validation Error'})
    def post(self):
        data = request.get_json()
        
        if User.query.filter_by(email=data['email']).first():
            return {'message': 'Email already registered'}, 400

        hashed_password = generate_password_hash(data['password'])
        new_user = User(email=data['email'], password=hashed_password, is_admin=False)
        
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(user_model)
    @auth_ns.doc(responses={200: 'Success', 401: 'Unauthorized'})
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not check_password_hash(user.password, data['password']):
            return {'message': 'Invalid credentials'}, 401

        access_token = create_access_token(identity=str(user.id))
        return {
            'access_token': access_token,
            'is_admin': user.is_admin
        }, 200

@posts_ns.route('/')
class PostList(Resource):
    @posts_ns.doc(security='jwt')
    @posts_ns.marshal_list_with(post_response)
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        posts = Post.query.order_by(Post.id.desc()).all()
        
        return [{
            'id': post.id,
            'content': post.content,
            'author_email': post.author.email,
            'user_id': post.user_id
        } for post in posts], 200

    @posts_ns.doc(security='jwt')
    @posts_ns.expect(post_model)
    @jwt_required()
    def post(self):
        data = request.get_json()
        user_id = get_jwt_identity()
        new_post = Post(content=data['content'], user_id=user_id)
        
        db.session.add(new_post)
        db.session.commit()

        return {'message': 'Post created successfully'}, 201

@posts_ns.route('/<int:post_id>')
class PostResource(Resource):
    @posts_ns.doc(security='jwt')
    @posts_ns.marshal_with(post_response)
    @jwt_required()
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        return {
            'id': post.id,
            'content': post.content,
            'author_email': post.author.email,
            'user_id': post.user_id
        }, 200

    @posts_ns.doc(security='jwt')
    @posts_ns.expect(post_model)
    @jwt_required()
    def put(self, post_id):
        data = request.get_json()
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        post = Post.query.get_or_404(post_id)

        if not (current_user.is_admin or str(post.user_id) == str(user_id)):
            return {'message': 'Unauthorized'}, 403

        post.content = data['content']
        db.session.commit()

        return {'message': 'Post updated successfully'}, 200

    @posts_ns.doc(security='jwt')
    @jwt_required()
    def delete(self, post_id):
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        post = Post.query.get_or_404(post_id)

        if not (current_user.is_admin or str(post.user_id) == str(user_id)):
            return {'message': 'Unauthorized'}, 403

        db.session.delete(post)
        db.session.commit()

        return {'message': 'Post deleted successfully'}, 200

@users_ns.route('/<int:user_id>')
class UserById(Resource):
    @users_ns.doc(security='jwt')
    @users_ns.marshal_with(user_response)
    @jwt_required()
    def get(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user.is_admin:
            return {'message': 'Unauthorized - Admin access required'}, 403

        user = User.query.get_or_404(user_id)
        return {
            'id': user.id,
            'email': user.email,
            'is_admin': user.is_admin,
            'post_count': len(user.posts)
        }, 200

    @users_ns.doc(security='jwt')
    @users_ns.expect(user_update_model)
    @jwt_required()
    def put(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        user_to_update = User.query.get_or_404(user_id)

        if user_to_update.is_admin:
            return {'message': 'Admin account cannot be modified'}, 403

        if not (current_user.is_admin or str(current_user_id) == str(user_id)):
            return {'message': 'Unauthorized'}, 403

        data = request.get_json()

        if 'email' in data:
            user_to_update.email = data['email']

        if 'password' in data:
            user_to_update.password = generate_password_hash(data['password'])

        db.session.commit()

        return {'message': 'User updated successfully'}, 200

    @users_ns.doc(security='jwt')
    @jwt_required()
    def delete(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        user_to_delete = User.query.get_or_404(user_id)

        if user_to_delete.is_admin:
            return {'message': 'Admin account cannot be deleted'}, 403

        if not (current_user.is_admin or str(current_user_id) == str(user_id)):
            return {'message': 'Unauthorized'}, 403

        db.session.delete(user_to_delete)
        db.session.commit()

        return {'message': 'User deleted successfully'}, 200

@users_ns.route('/')
class UserList(Resource):
    @users_ns.doc(security='jwt')
    @users_ns.marshal_list_with(user_response)
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if current_user.is_admin:
            users = User.query.all()
        else:
            users = [current_user]

        return [{
            'id': user.id,
            'email': user.email,
            'post_count': len(user.posts)
        } for user in users], 200
    
@posts_ns.route('/user/<int:user_id>')
class UserPosts(Resource):
    @posts_ns.doc(security='jwt')
    @posts_ns.marshal_list_with(post_response)
    @jwt_required()
    def get(self, user_id):
      
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404

        if not (current_user.is_admin or str(current_user_id) == str(user_id)):
            return {'message': 'Unauthorized'}, 403

        posts = Post.query.filter_by(user_id=user_id).order_by(Post.id.desc()).all()

        response = [{
            'id': post.id,
            'content': post.content,
            'created_at': post.created_at,
            'author_email': post.author.email,
            'user_id': post.user_id,
            'is_owner': str(post.user_id) == str(current_user_id) or current_user.is_admin
        } for post in posts]

        return response, 200