import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from models.users import UserSchema
from bson.objectid import ObjectId
from marshmallow import ValidationError

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.secret_key = os.getenv("SECRET_KEY")

# Initialize PyMongo and Bcrypt
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# User collection
users_collection = mongo.db.users

# Initialize the user schema
user_schema = UserSchema()

@app.route('/')
def home():
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.form.to_dict()
            data['userId'] = str(uuid.uuid4())
            if 'role' not in data or not data['role']:
                data['role'] = 'user'
            user_data = user_schema.load(data)
        except ValidationError as err:
            for field, errors in err.messages.items():
                for error in errors:
                    flash(f"Error in {field}: {error}", "error")
            return redirect(url_for('register'))

        first_name = user_data['firstName']
        last_name = user_data['lastName']
        email = user_data['email']
        password = user_data['password']
        role = user_data['role']

        if users_collection.find_one({'email': email}):
            flash('Email address already in use', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_collection.insert_one({
            'userId': user_data['userId'],
            'firstName': first_name,
            'lastName': last_name,
            'email': email,
            'password': hashed_password,
            'role': role
        })

        session['user_id'] = user_data['userId']
        session['email'] = email
        session['role'] = role

        flash('Registration successful!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_collection.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['userId']
            session['email'] = user['email']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Profile route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({'userId': session['user_id']})
    return render_template('profile.html', user=user)

# View all users route
@app.route('/users')
def view_users():
    if 'user_id' not in session or session['role'] not in ['admin', 'powerUser']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))

    users = users_collection.find()
    return render_template('users.html', users=users)

# View single user route
@app.route('/users/<user_id>')
def view_user(user_id):
    if 'user_id' not in session or session['role'] not in ['admin', 'powerUser']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if user:
        return render_template('user.html', user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('view_users'))

if __name__ == '__main__':
    app.run(debug=True)
