from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from chat import get_response
import os
import create_tags

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful', 'success')
            return redirect(url_for('api_key_management'))
        flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/delete_value/<tag>', methods=['DELETE'])
def delete_value(tag):
    api_key = request.headers.get('API-Key')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
                result = create_tags.delete_value(tag)
                return result
            else:
                flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to delete values', 'error')
        return redirect(url_for('login'))

@app.route('/api_key_management')
def api_key_management():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_keys = ApiKey.query.filter_by(user_id=user_id).all()
            return render_template('api_keys.html', api_keys=api_keys)
        else:
            flash('Invalid user', 'error')
            return redirect(url_for('login'))
    else:
        flash('Please log in to view API keys', 'error')
        return redirect(url_for('login'))


@app.route('/generate_api_key', methods=['POST'])
def generate_api_key():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            # Get the API key from the request data
            key_id = request.get_json().get("api_key")

            # Check if the API key already exists for the user
            existing_api_key = ApiKey.query.filter_by(key=key_id, user_id=user_id).first()
            if existing_api_key:
                flash('API key already exists', 'error')
            else:
                api_key = ApiKey(key=key_id, user_id=user_id)
                db.session.add(api_key)
                db.session.commit()
                flash('API key generated successfully', 'success')
                return jsonify({'success': True, 'api_key': key_id})
        else:
            flash('Invalid user', 'error')
    else:
        flash('Please log in to generate an API key', 'error')
    return jsonify({'success': False, 'api_key': None})

@app.route('/delete_api_key/<string:key_id>', methods=['POST'])
def delete_api_key(key_id):
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key = ApiKey.query.filter_by(key=key_id, user_id=user_id).first()
            if api_key:
                db.session.delete(api_key)
                db.session.commit()
                flash('API key deleted successfully', 'success')
                return jsonify({'success': True})
            else:
                flash('API key not found', 'error')
        else:
            flash('Invalid user', 'error')
    else:
        flash('Please log in to delete API keys', 'error')
    return jsonify({'success': False})

@app.route('/create_tag')
def display_items():
    apikey = request.args.get('apikey')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=apikey, user_id=user_id).first()
            if api_key_obj:
                result = create_tags.display_items()
                return result
            else:
                flash('Invalid API key or user', 'error')
                return redirect(url_for('login'))
        else:
            flash('Please log in to create tags', 'error')
            return redirect(url_for('login'))

@app.route('/create_tag', methods=['POST'])
def create_tag():
    api_key = request.headers.get('API-Key')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
               print(api_key_obj)
               result = create_tags.create_tag()
               return result
            else:
              flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to create tags', 'error')
    return redirect(url_for('login'))

@app.route('/update_value/<tag>', methods=['GET', 'POST'])
def update_value(tag):
    api_key = request.headers.get('API-Key')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
               result = create_tags.update_value(tag)
               return result
            else:
              flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to update values', 'error')
    return redirect(url_for('login'))

@app.route('/train')
def train():
    api_key = request.headers.get('API-Key')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
              return os.system('python3 train.py')
            else:
              flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to train', 'error')
    return redirect(url_for('login'))

@app.route('/predict', methods=['POST'])
def predict():
    text = request.get_json().get("message")
    api_key = request.args.get("apikey")
    userid = request.args.get("userid")

    apikey = ApiKey.query.filter_by(key=api_key,user_id=userid).first()

    if apikey:
        response = get_response(text)
        message = {"answer": response}
    else:
        message = {"answer": "Invalid API key"}

    return jsonify(message)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
