import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange, Email
from cryptography.fernet import Fernet
# For file uploads
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename

# --- Configuration ---

# Get the base directory of the project
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# This SECRET_KEY is crucial for session management and form protection (CSRF)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_you_should_change'
# Set up the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
# Limit upload size, e.g., 2MB
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
# This tells flask-login where to redirect users if they try to access a protected page
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Encryption Setup ---
KEY_FILE = 'secret.key'

def load_or_generate_key():
    """
    Loads the secret key from KEY_FILE or generates a new one.
    """
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

# Load the key and create the cipher suite
key = load_or_generate_key()
cipher_suite = Fernet(key)

# Allowed extensions for file upload (Test #8)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database Model ---

@login_manager.user_loader
def load_user(user_id):
    """Required by Flask-Login to load the current user from the session."""
    return User.query.get(int(user_id))

# UserMixin adds the required fields for Flask-Login (e.g., is_authenticated)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    # Storing the *hash*, not the password. 60 chars for bcrypt hash.
    password_hash = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}')"

    def set_password(self, password):
        """Hashes the password and stores it."""
        # Feature: Store hashed passwords (bcrypt)
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)
    

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Feature: Input Forms
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    notes_encrypted = db.Column(db.LargeBinary, nullable=True)
    # Link the expense to a user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Expense('{self.category}', '{self.amount}')"
    
class UpdateProfileForm(FlaskForm):
    # Feature: Profile Update Page
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()]) # (Test #15)
    submit = SubmitField('Update Profile')

    def validate_username(self, username):
        """Validate username change"""
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is already taken.')

    def validate_email(self, email):
        """Validate email change"""
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already in use.')
class AuditLog(db.Model):
    # Feature: Audit / Activity Logs
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.now())
    # Link the log to a user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"AuditLog('{self.user_id}', '{self.action}')"
# --- Forms (using Flask-WTF) ---

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # Feature: Password Validation
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    
    # Feature: Password Match Check (Test #13)
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        """Checks for duplicate usernames (Test #11)"""
        user = User.query.filter_by(username=username.data).first()
    
        if user:
            raise ValidationError('That username is already taken. Please choose another.')
        
    def validate_email(self, email):
        """Checks for duplicate emails"""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose another.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ExpenseForm(FlaskForm):
    # Feature: Input Forms
    # Test #12 (Number Field Validation)
    amount = DecimalField('Amount', 
                          validators=[DataRequired(), NumberRange(min=0.01)], 
                          places=2) 
    
    category = StringField('Category', validators=[DataRequired(), Length(min=2, max=100)])
    
    # Test #10 (Input Length Validation)
    notes = StringField('Notes', validators=[Length(max=200)]) 
    receipt = FileField('Upload Receipt (Optional)', 
                        validators=[FileAllowed(ALLOWED_EXTENSIONS, 'Images/PDFs only!')])
    submit = SubmitField('Add Expense')

# --- Routes (Views) ---

@app.route('/')
@app.route('/home')
def home():
    # If the user is already logged in, send them to the dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Otherwise, show them the new landing page
    return render_template('home.html', title='Welcome')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        # This block runs only if the form passed all validation
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data) # Hash the password
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    else:
        # If form validation fails, it will automatically pass error messages
        # to the template. This handles Test #2 (Weak Password), #13, #11, #20.
        pass

    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # Check if user exists and password is correct
        if user and user.check_password(form.password.data):
            login_user(user) # Feature: Session Management
            flash('Login successful!', 'success')
            
            # This logic is for Test #4 (Unauthorized Access)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            # Generic error message to prevent info leakage (Test #9)
            flash('Login unsuccessful. Please check username and password.', 'danger')
            
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user() # Feature: Session Management (Test #6)
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required 
def dashboard():
    form = ExpenseForm()

    if form.validate_on_submit():
        # --- ENCRYPTION LOGIC ---
        notes_data = form.notes.data.encode('utf-8')
        encrypted_notes = cipher_suite.encrypt(notes_data)

        receipt_filename = None # Default to no file

        # --- FILE UPLOAD LOGIC (Test #8) ---
        file = form.receipt.data
        if file and allowed_file(file.filename):
            # Make the filename secure (prevents path traversal attacks)
            filename = secure_filename(file.filename)

            # Create uploads directory if it doesn't exist
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            receipt_filename = filename # We'd save this to the DB
        # ------------------------------------

        expense = Expense(amount=float(form.amount.data), 
                          category=form.category.data, 
                          notes_encrypted=encrypted_notes, 
                          user_id=current_user.id)
                          # (Note: We'd also add receipt_filename to the Expense model)

        log_action = f"Added expense: {form.category.data} - ${form.amount.data}"
        if receipt_filename:
            log_action += f" (with receipt: {receipt_filename})"

        log_entry = AuditLog(action=log_action, user_id=current_user.id)

        db.session.add(expense)
        db.session.add(log_entry)
        db.session.commit()

        flash('Expense added successfully!', 'success')
        return redirect(url_for('dashboard')) 

    # --- DECRYPTION LOGIC (on load) ---
    # Feature: Data Storage Layer (Test #7, #18)
    expenses_db = Expense.query.filter_by(user_id=current_user.id).all()
    expenses_decrypted = []
    for exp in expenses_db:
        try:
            # Decrypt the notes for display
            decrypted_note = cipher_suite.decrypt(exp.notes_encrypted).decode('utf-8')
            exp.notes = decrypted_note # Add a temporary 'notes' attribute
        except Exception as e:
            exp.notes = "[Error: Cannot decrypt data]"
        expenses_decrypted.append(exp)
    # ------------------------------------

    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).all()

    return render_template('dashboard.html', 
                           title='Dashboard', 
                           form=form, 
                           expenses=expenses_decrypted, # Pass decrypted list
                           logs=logs)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Feature: Profile Update Page (Test #14)
    form = UpdateProfileForm()
    if form.validate_on_submit():
        # This runs when the form is submitted and valid
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()

        # Log this action
        log_entry = AuditLog(action="Updated profile", user_id=current_user.id)
        db.session.add(log_entry)
        db.session.commit()

        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))

    elif request.method == 'GET':
        # This runs when the page is first loaded
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('profile.html', title='Profile', form=form)


# --- Error Handlers (Test #9, #17) ---

@app.errorhandler(404)
def error_404(error):
    """Handles Not Found errors."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def error_500(error):
    """Handles internal server errors."""
    # We must manually roll back the session in case a DB error caused this
    db.session.rollback() 
    return render_template('500.html'), 500

# --- Run the App ---
if __name__ == '__main__':
    # This block creates the database file if it doesn't exist
    with app.app_context():
        db.create_all()
    app.run(debug=False)