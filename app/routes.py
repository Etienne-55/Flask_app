from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models import User, Post
from app import db

main = Blueprint('main', __name__)

@main.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(email=data['email'], password=hashed_password, is_admin=False)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@main.route('/register/admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    
    if User.query.filter_by(is_admin=True).first():
        return jsonify({'message': 'Admin already exists'}), 400

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(data['password'])
    new_admin = User(email=data['email'], password=hashed_password, is_admin=True)
    
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'message': 'Admin user created successfully'}), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        'access_token': access_token,
        'is_admin': user.is_admin
    }), 200

@main.route('/posts', methods=['GET'])
@jwt_required()
def get_posts():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    posts = Post.query.order_by(Post.id.desc()).all()
    
    return jsonify([{
        'id': post.id,
        'content': post.content,
        'created_at': post.created_at,
        'author_email': post.author.email,
        'user_id': post.user_id,
        'is_owner': str(post.user_id) == str(current_user_id) or current_user.is_admin
    } for post in posts]), 200

@main.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json()
    
    if not data or not data.get('content'):
        return jsonify({'message': 'Missing content'}), 400

    user_id = get_jwt_identity()
    new_post = Post(content=data['content'], user_id=user_id)
    
    db.session.add(new_post)
    db.session.commit()

    return jsonify({'message': 'Post created successfully'}), 201

@main.route('/posts/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    data = request.get_json()
    user_id = get_jwt_identity()
    current_user = User.query.get(user_id)
    post = Post.query.get_or_404(post_id)

    if not data or not data.get('content'):
        return jsonify({'message': 'Missing content'}), 400

    if not (current_user.is_admin or str(post.user_id) == str(user_id)):
        return jsonify({'message': 'Unauthorized'}), 403

    post.content = data['content']
    db.session.commit()

    return jsonify({
        'message': 'Post updated successfully',
        'updated_post': {
            'id': post.id,
            'content': post.content,
            'author_email': post.author.email
        }
    }), 200

@main.route('/posts/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    user_id = get_jwt_identity()
    current_user = User.query.get(user_id)
    post = Post.query.get_or_404(post_id)

    if not (current_user.is_admin or str(post.user_id) == str(user_id)):
        return jsonify({'message': 'Unauthorized'}), 403

    db.session.delete(post)
    db.session.commit()

    return jsonify({'message': 'Post deleted successfully'}), 200

@main.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    user_id = get_jwt_identity()
    current_user = User.query.get(user_id)

    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized - Admin access required'}), 403

    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'email': user.email,
        'is_admin': user.is_admin,
        'post_count': len(user.posts)
    } for user in users]), 200

@main.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    admin_id = get_jwt_identity()
    admin_user = User.query.get(admin_id)

    if not admin_user.is_admin:
        return jsonify({'message': 'Unauthorized - Admin access required'}), 403

    user_to_delete = User.query.get_or_404(user_id)
    
    if user_to_delete.is_admin:
        return jsonify({'message': 'Cannot delete admin user'}), 403

    Post.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'message': 'User and their posts deleted successfully'}), 200

@main.route('/user/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided'}), 400

    if 'email' in data:
        if User.query.filter_by(email=data['email']).first() and data['email'] != user.email:
            return jsonify({'message': 'Email already exists'}), 400
        user.email = data['email']

    if 'password' in data:
        user.password = generate_password_hash(data['password'])

    db.session.commit()
    return jsonify({'message': 'Profile updated successfully'}), 200

@main.route('/user/delete', methods=['DELETE'])
@jwt_required()
def delete_own_account():
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    if user.is_admin:
        return jsonify({'message': 'Admin account cannot be deleted'}), 403

    Post.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Account deleted successfully'}), 200

@main.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def admin_update_user(user_id):
    admin_id = get_jwt_identity()
    admin_user = User.query.get(admin_id)

    if not admin_user.is_admin:
        return jsonify({'message': 'Unauthorized - Admin access required'}), 403

    user_to_update = User.query.get_or_404(user_id)
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided'}), 400

    if user_to_update.is_admin and user_to_update.id != admin_id:
        return jsonify({'message': 'Cannot modify another admin\'s profile'}), 403

    if 'email' in data:
        if User.query.filter_by(email=data['email']).first() and data['email'] != user_to_update.email:
            return jsonify({'message': 'Email already exists'}), 400
        user_to_update.email = data['email']

    if 'password' in data:
        user_to_update.password = generate_password_hash(data['password'])

    db.session.commit()
    return jsonify({'message': 'User profile updated successfully'}), 200

@main.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_user(user_id):
    admin_id = get_jwt_identity()
    admin_user = User.query.get(admin_id)

    if not admin_user.is_admin:
        return jsonify({'message': 'Unauthorized - Admin access required'}), 403

    user_to_delete = User.query.get_or_404(user_id)

    if user_to_delete.is_admin:
        return jsonify({'message': 'Cannot delete admin accounts'}), 403

    Post.query.filter_by(user_id=user_id).delete()
    
    db.session.delete(user_to_delete)
    db.session.commit()

    return jsonify({'message': 'User and their posts deleted successfully'}), 200