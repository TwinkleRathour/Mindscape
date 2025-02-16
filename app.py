from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from pathlib import Path

app = Flask(__name__)
# Ensure the instance folder exists
instance_path = Path('instance')
instance_path.mkdir(exist_ok=True)

# Set database path
db_path = instance_path / 'users.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Home Route
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('pswd')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


# User Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('txt')
        email = request.form.get('email')
        password = request.form.get('pswd')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['username'] = new_user.username
        flash('Account created successfully!', 'success')
        return redirect(url_for('home'))
    
    return render_template('login.html')


@app.route('/ml')
def ml():
    return render_template('ml.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/ai')
def ai():
    return render_template('ai.html')

@app.route('/project')
def project():
    return render_template('project.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            print(f"Database created successfully at {db_path}")
        except Exception as e:
            print(f"Error creating database: {str(e)}")
    app.run(debug=True)
