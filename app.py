from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import uuid
import jwt
import datetime


# seguir en

# init app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'claveultrasecreta'

basedir = os.path.abspath(os.path.dirname(__file__))

# App config
app.config['SECRET_KEY'] = 'claveultrasecreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'todo.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'False'

# Init db
db = SQLAlchemy(app)

# init Marshmallow
ma = Marshmallow(app)

# DB Models


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(10))
    completed = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

# User Schema


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'public_id', 'name', 'password', 'admin')

# task List Schema


class TaskSchema(ma.Schema):
    class Meta:
        fields = ('id', 'text', 'completed', 'user_id')


# Init Schemas
user_schema = UserSchema()
users_schema = UserSchema(many=True)
task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'error': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def all_users(current_user):
    if not current_user.admin:
        return jsonify({'error': 'Cannot do that sheet'})

    users = User.query.all()

    result = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        result.append(user_data)

    return jsonify({'users': result})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'error': 'Cannot do that sheet'})

    user = request.get_json()
    hashed_pw = generate_password_hash(user['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),
                    name=user['name'], password=hashed_pw, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return user_schema.jsonify(new_user)


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'error': 'Cannot do that sheet'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'error': 'Not found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def change_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'error': 'Cannot do that sheet'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'error': 'Not found'})

    user_data = request.get_json()

    user.name = user_data['name']
    user.password = hashed_pw = generate_password_hash(
        user_data['password'], method='sha256')
    user.admin = user_data['admin']
    db.session.commit()
    return jsonify({'name': user.name, 'public_id': user.public_id, 'admin': user.admin})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(create_user, public_id):
    if not current_user.admin:
        return jsonify({'error': 'Cannot do that sheet'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'error': 'Not found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'name': user.name, 'public_id': user.public_id, 'admin': user.admin})


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'www-authenticate': 'Basic realm="login required!"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'www-authenticate': 'Basic realm="login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    else:
        return make_response('Could not verify', 401, {'www-authenticate': 'Basic realm="login required!"'})


@app.route('/task', methods=['GET'])
@token_required
def all_tasks(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return tasks_schema.jsonify(tasks)


@app.route('/task', methods=['POST'])
@token_required
def add_task(current_user):
    data = request.get_json()
    new_todo = Task(text=data['text'], completed=False,
                    user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({"id": new_todo.id, "text": new_todo.text})


@app.route('/task/<task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    data = request.get_json()
    task = Task.query.filter_by(id=task_id).first()
    print(task)
    if not task:
        return jsonify({"error": "Task not found!!"})
    task.text = data['text']
    task.completed = data['completed']
    db.session.commit()
    return jsonify({"id": task.id, "text": task.text, "completed": task.completed})


@app.route('/task/<task_id>', methods=['GET'])
@token_required
def one_task(current_user, task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({"error": "Task not found!!"})
    return task_schema.jsonify(task)


@app.route('/task/<task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({"error": "Task not found!!"})
    db.session.delete(task)
    db.session.commit()
    return task_schema.jsonify(task)


if __name__ == '__main__':
    app.run(debug=True)
