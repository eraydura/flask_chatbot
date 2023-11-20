from flask import Flask, render_template, request,abort, redirect, url_for, flash, session, jsonify,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from sqlalchemy.exc import IntegrityError
from chat import get_response
from train import train_model
from flask_wtf.file import FileField, FileAllowed
from PIL import Image
import numpy as np
import base64
from io import BytesIO
from flask_mail import Mail, Message
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Configuration of mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465  # Updated port for TLS
app.config['MAIL_USE_TLS'] = False  # Use TLS instead of SSL
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'eraydura@gmail.com'
app.config['MAIL_PASSWORD'] = 'idjn qxtt eeep qlun'
app.config['MAIL_DEFAULT_SENDER'] = 'eraydura@gmail.com'

mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    offer = db.Column(db.String(200), nullable=False, default="Free")
    password = db.Column(db.String(200), nullable=False)
    user_image = db.Column(db.LargeBinary, nullable=True)
    confirmation_code = db.Column(db.String(16), unique=True, nullable=True)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tags = db.relationship('Tag', backref='api_key', lazy=True)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag_name = db.Column(db.String(50), unique=True, nullable=False)
    pattern = db.Column(db.String(200), nullable=False)
    response = db.Column(db.String(200), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_key.id'))

class ChatbotFeature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    color = db.Column(db.String(20))
    chatbot_name = db.Column(db.String(50))
    chatbot_text = db.Column(db.String(200))
    chatbot_not_response = db.Column(db.String(200),default="I don't know")
    chatbot_message = db.Column(db.String(200),default="Write a message...")
    chatbot_image = db.Column(db.LargeBinary)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_key.id'))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    company = StringField('Company', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    user_image = FileField('Profile Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChatbotFeatureForm(FlaskForm):
    color = StringField('Color', validators=[DataRequired()])
    chatbot_name = StringField('Chatbot Name', validators=[DataRequired()])
    chatbot_text = StringField('Chatbot Text', validators=[DataRequired()])
    chatbot_nottext = StringField('Chatbot Response', validators=[DataRequired()])
    chatbot_write = StringField('Chatbot Write', validators=[DataRequired()])
    chatbot_image = FileField('Chatbot Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Create Feature')

def send_registration_email(email, confirmation_code):
    subject = 'Confirm Your Registration'
    body = f'Thank you for registering. Please click the following link to confirm your registration: {url_for("confirm_registration", code=confirmation_code, _external=True)}'
    message = Message(subject, recipients=[email], body=body)
    try:
        mail.send(message)
    except Exception as e:
        print(f"Error sending email: {str(e)}")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        company = form.company.data
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            print(hashed_password)
            new_user = User(username=username, email=email, company=company, password=hashed_password)

            # Save a unique confirmation code for the user
            confirmation_code = secrets.token_urlsafe(16)
            new_user.confirmation_code = confirmation_code

            db.session.add(new_user)
            db.session.commit()

            # Send registration email
            send_registration_email(email, confirmation_code)

            flash('Registration successful. Check your email for confirmation.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/confirm_registration/<code>', methods=['GET'])
def confirm_registration(code):
    user = User.query.filter_by(confirmation_code=code).first()
    print(user)
    if user:
        user.confirmed = True
        user.confirmation_code = None  
        db.session.commit()
        flash('Email confirmation successful. You can now log in.', 'success')
    else:
        flash('Invalid confirmation code.', 'error')
    return redirect(url_for('login'))

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
            # Generate a random API key
            api_key = secrets.token_urlsafe(32)

            # Check if the API key already exists for the user
            existing_api_key = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            while existing_api_key:
                # Regenerate a new API key if it already exists
                api_key = secrets.token_urlsafe(32)
                existing_api_key = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()

            api_key_obj = ApiKey(key=api_key, user_id=user_id)
            db.session.add(api_key_obj)
            db.session.commit()
            flash('API key generated successfully', 'success')
            return jsonify({'success': True, 'api_key': api_key})
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
                # Delete associated chatbot features
                chatbot_features = ChatbotFeature.query.filter_by(api_key_id=api_key.id).all()
                for feature in chatbot_features:
                    db.session.delete(feature)

                # Delete associated tags
                tags = Tag.query.filter_by(api_key_id=api_key.id).all()
                for tag in tags:
                    db.session.delete(tag)

                # Delete the API key
                db.session.delete(api_key)
                db.session.commit()

                flash('API key and associated data deleted successfully', 'success')
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
                tags = Tag.query.filter_by(api_key_id=api_key_obj.id).all()
                
                return render_template('Creating_tags.html', tags=tags)
            else:
                flash('Invalid API key or user', 'error')
                return redirect(url_for('login'))
        else:
            flash('Please log in to create tags', 'error')
            return redirect(url_for('login'))
    else:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))

@app.route('/delete_value/<tag>', methods=['DELETE'])
def delete_value(tag):
    api_key = request.headers.get('API-Key')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
                tag_to_delete = Tag.query.filter_by(tag_name=tag, api_key_id=api_key_obj.id).first()
                if tag_to_delete:
                    try:
                        db.session.delete(tag_to_delete)
                        db.session.commit()
                        flash(f'Value for tag "{tag}" deleted successfully', 'success')
                        return jsonify({'message': f'Value for tag "{tag}" deleted successfully'})
                    except IntegrityError:
                        db.session.rollback()
                        flash('Error deleting tag value', 'error')
                        return jsonify({'error': 'Error deleting tag value'})
                else:
                    flash(f'Tag "{tag}" not found', 'error')
                    return jsonify({'error': f'Tag "{tag}" not found'})
            else:
                flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to delete values', 'error')
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
                if request.method == 'POST':
                    tag_name = request.json.get('tag_name')
                    pattern = request.json.get('pattern')
                    response = request.json.get('response')

                    new_tag = Tag(tag_name=tag_name, pattern=pattern, response=response, api_key_id=api_key_obj.id)

                    try:
                        db.session.add(new_tag)
                        db.session.commit()
                        flash('New tag created successfully', 'success')
                        return jsonify({'message': 'New tag created successfully'})
                    except IntegrityError:
                        db.session.rollback()
                        flash('Error creating new tag', 'error')
                        return jsonify({'error': 'Error creating new tag'})
                else:
                    flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to create tags', 'error')
    return redirect(url_for('login'))

@app.route('/update_tag/<int:tag_id>', methods=['POST'])
def update_tag(tag_id):
    api_key = request.headers.get('API-Key')

    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()

            if api_key_obj:
                tag_to_update = Tag.query.filter_by(api_key_id=api_key_obj.id)
                tag_to_update=tag_to_update[tag_id]
                print(tag_to_update.tag_name)
                if tag_to_update is None:
                    flash(f'Tag with ID "{tag_id}" not found', 'error')
                    return jsonify({'error': f'Tag with ID "{tag_id}" not found'})

                # Get the updated values from the JSON payload
                new_tag_name = request.json.get('tag_name')
                new_pattern = request.json.get('pattern')
                new_response = request.json.get('response')

                # Update the tag values
                tag_to_update.tag_name = new_tag_name
                tag_to_update.pattern = new_pattern
                tag_to_update.response = new_response

                try:
                    db.session.commit()
                    flash(f'Tag with ID "{tag_id}" updated successfully', 'success')
                    return jsonify({'message': f'Tag with ID "{tag_id}" updated successfully'})
                except IntegrityError:
                    db.session.rollback()
                    flash('Error updating tag. Integrity error.', 'error')
                    return jsonify({'error': 'Error updating tag. Integrity error.'})
            else:
                flash('Invalid API key or user', 'error')
    else:
        flash('Please log in to update tags', 'error')

    return jsonify({'error': 'Update operation failed'})

def allowed_file(filename):
    # Add any file type extensions you want to allow
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


@app.route('/save_chatbot_feature', methods=['POST'])
def save_chatbot_feature():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user and request.method == 'POST':
            api_key = request.args.get('apikey')

            # Check if the provided API key and user ID are valid
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
                color = request.form.get('color')
                chatbot_name = request.form.get('chatbot_name')
                chatbot_text = request.form.get('chatbot_text')
                chatbot_not_response = request.form.get('chatbot_nottext')
                chatbot_write = request.form.get('chatbot_write')
                chatbot_image = request.files.get('chatbot_image')

                if chatbot_image and allowed_file(chatbot_image.filename):
                    # Open the image and convert to NumPy array
                    image = Image.open(chatbot_image)
                    image_array = np.array(image)

                    # Convert NumPy array to bytes
                    image_bytes = BytesIO()
                    Image.fromarray(image_array).save(image_bytes, format='PNG')
                    image_bytes = image_bytes.getvalue()

                    existing_feature = ChatbotFeature.query.filter_by(api_key_id=api_key_obj.id).first()

                    if existing_feature:
                        existing_feature.color = color
                        existing_feature.chatbot_name = chatbot_name
                        existing_feature.chatbot_text = chatbot_text
                        existing_feature.chatbot_not_response = chatbot_not_response
                        existing_feature.chatbot_message = chatbot_write
                        existing_feature.chatbot_image = image_bytes

                        try:
                            db.session.commit()
                            flash('Chatbot feature updated successfully', 'success')
                            return jsonify({'message': 'Chatbot feature updated successfully'})
                        except Exception as e:
                            db.session.rollback()
                            flash(f'Error updating chatbot feature: {str(e)}', 'error')
                            return jsonify({'error': f'Error updating chatbot feature: {str(e)}'})
                    else:
                        # Create a new feature with the image array
                        new_feature = ChatbotFeature(
                            color=color,
                            chatbot_name=chatbot_name,
                            chatbot_text=chatbot_text,
                            chatbot_not_response=chatbot_not_response,
                            chatbot_message=chatbot_write,
                            chatbot_image=image_bytes, 
                            api_key_id=api_key_obj.id
                        )

                        try:
                            db.session.add(new_feature)
                            db.session.commit()
                            flash('New chatbot feature added successfully', 'success')
                            return jsonify({'message': 'New chatbot feature added successfully'})
                        except Exception as e:
                            db.session.rollback()
                            flash(f'Error adding new chatbot feature: {str(e)}', 'error')
                            return jsonify({'error': f'Error adding new chatbot feature: {str(e)}'})
                else:
                    flash('Invalid file type for chatbot image or image not provided', 'error')
                    return jsonify({'error': 'Invalid file type for chatbot image or image not provided'})
            else:
                flash('Invalid API key or user', 'error')
                return jsonify({'error': 'Invalid API key or user'})
        else:
            flash('Invalid API key or user', 'error')
            return jsonify({'error': 'Invalid API key or user'})
    else:
        flash('Please log in to organization features', 'error')
        return redirect(url_for('login'))
        
@app.route('/chatbot_features', methods=['GET'])
def get_features():
    api_key = request.args.get('apikey')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
        if user and api_key_obj:
            return render_template('chatfeature.html')
        else:
            return jsonify({'error': 'Invalid API key or user'})
    else:
        flash('Please log in to organization features', 'error')
    return redirect(url_for('login'))

@app.route('/get_chatbot_features', methods=['GET'])
def get_chatbot_features():
    api_key = request.args.get('apikey')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()

        if user and api_key_obj:
            features = ChatbotFeature.query.filter_by(api_key_id=api_key_obj.id).all()

            # Prepare a JSON response
            feature_list = []
            for feature in features:
                feature_data = {
                    'color': feature.color,
                    'chatbot_name': feature.chatbot_name,
                    'chatbot_nottext': feature.chatbot_not_response,
                    'chatbot_write': feature.chatbot_message,
                    'chatbot_text': feature.chatbot_text,
                }

                # Convert NumPy array to image and encode as base64
                if feature.chatbot_image is not None:
                    try:
                        # Convert NumPy array to image
                        image_pil = Image.fromarray(feature.chatbot_image.astype('uint8'))

                        # Save the image to a temporary BytesIO object
                        image_bytes = BytesIO()
                        image_pil.save(image_bytes, format='PNG')

                        # Encode image as base64
                        feature_data['chatbot_image'] = base64.b64encode(image_bytes.getvalue()).decode('utf-8')
                    except Exception as e:
                        print(f"Error converting image: {str(e)}")
                        feature_data['chatbot_image'] = None
                else:
                    feature_data['chatbot_image'] = None

                feature_list.append(feature_data)

            return jsonify({'chatbot_features': feature_list})
        else:
            return jsonify({'error': 'Invalid API key or user'})
    else:
        flash('Please log in to organization features', 'error')
        return redirect(url_for('login'))


@app.route('/get_chatbot_image')
def get_chatbot_image():
    api_key = request.args.get('apikey')

    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()

        if user and api_key_obj:
            feature = ChatbotFeature.query.filter_by(api_key_id=api_key_obj.id).first()

            if feature and feature.chatbot_image is not None:
                try:
                    image_base64 = base64.b64encode(feature.chatbot_image).decode('utf-8')
                    return jsonify({'chatbot_image': image_base64})
                except Exception as e:
                    print(f"Error sending image: {str(e)}")

    return jsonify({'error': 'Invalid API key, user, or feature ID'})


@app.route('/train')
def train():
    api_key = request.headers.get('API-Key')
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user:
            api_key_obj = ApiKey.query.filter_by(key=api_key, user_id=user_id).first()
            if api_key_obj:
                tags = Tag.query.filter_by(api_key_id=api_key_obj.id).all()
                intents = []
                for tag in tags:
                    intent = {
                        "tag": tag.tag_name,
                        "patterns": [pattern.strip() for pattern in tag.pattern.split(',')],
                        "responses": [response.strip() for response in tag.response.split(',')]
                    }
                    intents.append(intent)
                # Create a dictionary with a key named "intents"
                json_data = {"intents": intents}
                
                FILE = "models/"+api_key+".pth"
                response = train_model(json_data, FILE)

                flash(f'Training successful for API key: {api_key}', 'success')
                return jsonify({'message': response})
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

    apikey = ApiKey.query.filter_by(key=api_key, user_id=userid).first()

    if apikey:
        tags = Tag.query.filter_by(api_key_id=apikey.id).all()
        features = ChatbotFeature.query.filter_by(api_key_id=apikey.id).all()

        if features:
            feature_text = features[0].chatbot_not_response
            intents = []
            for tag in tags:
                intent = {
                    "tag": tag.tag_name,
                    "patterns": [pattern.strip() for pattern in tag.pattern.split(',')],
                    "responses": [response.strip() for response in tag.response.split(',')]
                }
                intents.append(intent)
            FILE = "models/"+api_key+".pth"
            response = get_response(text, intents, FILE, feature_text)
            message = {"answer": response}
        else:
            message = {"answer": "Feature not found"}
    else:
        message = {"answer": "Invalid API key"}

    return jsonify(message)

# Route for the custom 404 error page
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404
    
@app.route('/user_info', methods=['GET'])
def user_info():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        
        if user and user.user_image:

            image_base64 = base64.b64encode(user.user_image).decode('utf-8')
            
            # Pass the base64-encoded image string to the template
            return render_template('userpage.html', user_info=user, user_image=image_base64)
        else:
            return render_template('userpage.html', user_info=user, user_image=None)
    else:
        flash('Please log in to organization features', 'error')
        return redirect(url_for('login'))


@app.route('/update_user', methods=['POST'])
def update_user():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            try:
                new_username = request.form.get('username')  # Change to form instead of json
                new_email = request.form.get('email')  # Change to form instead of json
                new_company = request.form.get('company')  # Change to form instead of json
                new_user_image = request.files.get('user_image')

                # Update the user information
                if new_username != "":
                    user.username = new_username
                if new_email != "":
                    user.email = new_email
                if new_company != "":
                    user.company = new_company

                if new_user_image and allowed_file(new_user_image.filename):

                    image = Image.open(new_user_image)
                    image_array = np.array(image)
                    image_bytes = BytesIO()
                    Image.fromarray(image_array).save(image_bytes, format='PNG')
                    image_bytes = image_bytes.getvalue()
                    user.user_image = image_bytes
                
                db.session.commit()

                flash('User information updated successfully', 'success')
                return jsonify({'message': 'User information updated successfully'})
            except Exception as e:
                print(f"Error updating user: {str(e)}")
                db.session.rollback()
                flash('Error updating user information', 'error')
                return jsonify({'error': 'Error updating user information'})
        else:
            flash('Invalid user', 'error')
            return jsonify({'error': 'Invalid user'})
    else:
        flash('Please log in to update user information', 'error')
        return jsonify({'error': 'Please log in to update user information'})

@app.route('/header')
def header():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user and user.user_image:
            user_image_base64 = base64.b64encode(user.user_image).decode('utf-8')
            return render_template('header.html', user_image=user_image_base64)
    return render_template('header.html', user_image=None)

@app.route('/not_found_route')
def not_found_route():
    abort(404)

@app.route('/generating')
def generating_code():
    api_key = request.args.get('apikey')
    if 'user_id' in session:
        user_id = session['user_id']
        return render_template('generated.html', api_key=api_key, userid=user_id)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
