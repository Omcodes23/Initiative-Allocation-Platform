from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
import string
import time
from datetime import datetime, timedelta, date
from pymongo import MongoClient
from bson import ObjectId
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from config import *

load_dotenv()

app = Flask(__name__)
app.secret_key = SECRET_KEY

# MongoDB Configuration with connection pooling
client = MongoClient(
    MONGO_URI,
    maxPoolSize=MONGO_MAX_POOL_SIZE,
    connectTimeoutMS=MONGO_CONNECT_TIMEOUT_MS,
    serverSelectionTimeoutMS=MONGO_SERVER_SELECTION_TIMEOUT_MS,
    retryWrites=True,
    retryReads=True
)
db = client.get_database()

# Configure Flask app for multi-user support
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=SESSION_TIMEOUT)

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Error handling middleware
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(413)
def too_large(error):
    return render_template('error.html', error_code=413, error_message="File too large"), 413

@app.errorhandler(429)
def too_many_requests(error):
    return render_template('error.html', error_code=429, error_message="Too many requests"), 429

# Request timeout middleware
@app.before_request
def before_request():
    # Set session as permanent
    session.permanent = True
    
    # Check if user is authenticated and session is valid
    if current_user.is_authenticated:
        try:
            # Verify user still exists in database
            user_data = db.users.find_one({'_id': ObjectId(current_user.id)})
            if not user_data:
                logout_user()
                flash('Your session has expired. Please login again.')
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error checking user session: {e}")
            logout_user()
            flash('Session error. Please login again.')
            return redirect(url_for('login'))
    
    # Rate limiting for API endpoints
    if request.endpoint and 'recent_notifications' in request.endpoint:
        # Limit notification polling to prevent spam
        if 'last_notification_check' in session:
            time_since_last = time.time() - session['last_notification_check']
            if time_since_last < 2:  # Minimum 2 seconds between checks
                return jsonify({'error': 'Rate limit exceeded'}), 429
        session['last_notification_check'] = time.time()

# File upload configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_otp(length=6):
    """Generate a numeric OTP"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def test_password_hashing():
    """Test function to verify password hashing works correctly"""
    test_password = "test123456"
    hashed = generate_password_hash(test_password)
    print(f"DEBUG: Test password: {test_password}")
    print(f"DEBUG: Test hash: {hashed}")
    print(f"DEBUG: Test verification: {check_password_hash(hashed, test_password)}")
    return check_password_hash(hashed, test_password)

def store_otp(email, otp):
    """Store OTP in database with expiration"""
    # Remove any existing OTP for this email
    db.password_reset_otps.delete_many({'email': email})
    
    # Store new OTP with 10-minute expiration
    otp_data = {
        'email': email,
        'otp': otp,
        'created_at': datetime.now(),
        'expires_at': datetime.now() + timedelta(minutes=10),
        'used': False
    }
    db.password_reset_otps.insert_one(otp_data)

def verify_otp(email, otp):
    """Verify OTP and mark as used if valid"""
    otp_record = db.password_reset_otps.find_one({
        'email': email,
        'otp': otp,
        'expires_at': {'$gt': datetime.now()},
        'used': False
    })
    
    if otp_record:
        # Mark OTP as used
        db.password_reset_otps.update_one(
            {'_id': otp_record['_id']},
            {'$set': {'used': True}}
        )
        return True
    return False

def send_email(to_email, subject, body):
    try:
        smtp_settings = db.smtp_settings.find_one()
        if not smtp_settings or not smtp_settings.get('enabled', False):
            return False
        
        msg = MIMEMultipart()
        msg['From'] = smtp_settings['email']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Auto-wrap plain-text bodies into basic HTML for better formatting
        html_body = body
        if '<html' not in body.lower():
            # Preserve all line breaks as <br> for simple readable formatting
            lines = [line.strip() for line in body.strip().split('\n')]
            html_body = '<br>'.join(lines)
            html_body = f"""
            <html>
            <body style='font-family: Arial, sans-serif; line-height: 1.6;'>
                {html_body}
            </body>
            </html>
            """
        
        html_body = html_body.replace('Initiative Platform Team', 'Operation Excellence Team')
        msg.attach(MIMEText(html_body, 'html'))
        
        server = smtplib.SMTP(smtp_settings['smtp_server'], smtp_settings['smtp_port'])
        server.starttls()
        server.login(smtp_settings['email'], smtp_settings['password'])
        server.sendmail(smtp_settings['email'], to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def safe_db_operation(operation, max_retries=3):
    """Safely execute database operations with retry logic"""
    for attempt in range(max_retries):
        try:
            return operation()
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Database operation failed after {max_retries} attempts: {e}")
                raise
            print(f"Database operation attempt {attempt + 1} failed: {e}")
            time.sleep(0.1 * (attempt + 1))  # Exponential backoff
    return None

def check_db_connection():
    """Check if database connection is healthy"""
    try:
        # Ping the database
        client.admin.command('ping')
        return True
    except Exception as e:
        print(f"Database connection check failed: {e}")
        return False

def get_db_connection_info():
    """Get database connection information for monitoring"""
    try:
        server_info = client.server_info()
        return {
            'status': 'connected',
            'version': server_info.get('version', 'unknown'),
            'connections': server_info.get('connections', {}),
            'uptime': server_info.get('uptime', 0)
        }
    except Exception as e:
        return {
            'status': 'disconnected',
            'error': str(e)
        }

def send_reminder_notifications():
    """Send reminder notifications and emails for due/overdue initiatives"""
    try:
        today = datetime.now().date()
        
        # Get all active initiatives with reminders enabled
        active_events = list(db.events.find({
            'status': {'$ne': 'completed'},
            'enable_reminders': True
        }))
        
        for event in active_events:
            # Get effective due date (revised or original)
            effective_due_date = event.get('revised_due_date') or event.get('due_date')
            if not effective_due_date:
                continue
                
            due_date = effective_due_date.date()
            days_until_due = (due_date - today).days
            is_overdue = days_until_due < 0
            
            # Check if reminder should be sent based on frequency
            reminder_frequency = event.get('reminder_frequency', 'weekly')
            should_send_reminder = False
            
            if reminder_frequency == 'daily':
                should_send_reminder = True
            elif reminder_frequency == 'weekly':
                # Send reminder if due within 7 days or overdue
                should_send_reminder = days_until_due <= 7
            elif reminder_frequency == 'monthly':
                # Send reminder if due within 30 days or overdue
                should_send_reminder = days_until_due <= 30
            elif reminder_frequency == 'quarterly':
                # Send reminder if due within 90 days or overdue
                should_send_reminder = days_until_due <= 90
            
            # Also send reminder if overdue regardless of frequency
            if is_overdue:
                should_send_reminder = True
            
            if should_send_reminder:
                # Send notifications to all assigned users
                for user_email in event.get('assigned_users', []):
                    # Create notification
                    notification_data = {
                        'type': 'reminder',
                        'user_email': user_email,
                        'event_id': str(event['_id']),
                        'event_title': event['title'],
                        'message': f'Reminder: Initiative "{event["title"]}" is {"overdue" if is_overdue else f"due in {days_until_due} days"}',
                        'created_at': datetime.now(),
                        'read': False,
                        'priority': 'high' if is_overdue else 'normal',
                        'days_until_due': days_until_due,
                        'is_overdue': is_overdue
                    }
                    db.notifications.insert_one(notification_data)
                    
                    # Send email if SMTP is enabled
                    smtp_settings = db.smtp_settings.find_one()
                    if smtp_settings and smtp_settings.get('enabled', False):
                        # Get user details
                        user_data = db.users.find_one({'email': user_email})
                        if user_data:
                            subject = f'{"🚨 OVERDUE" if is_overdue else "📅 Reminder"}: {event["title"]}'
                            
                            if is_overdue:
                                email_body = f"""
                                <html>
                                <body>
                                    <h2 style="color: #dc3545;">🚨 URGENT: Initiative Overdue</h2>
                                    <p>Hello {user_data['name']},</p>
                                    <p>The following initiative is <strong>OVERDUE</strong>:</p>
                                    
                                    <div style="background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                        <h3>{event['title']}</h3>
                                        <p><strong>Description:</strong> {event.get('description', 'N/A')}</p>
                                        <p><strong>Category:</strong> {event.get('category', 'N/A')}</p>
                                        <p><strong>Due Date:</strong> {effective_due_date.strftime('%Y-%m-%d')}</p>
                                        <p><strong>Days Overdue:</strong> {abs(days_until_due)} days</p>
                                    </div>
                                    
                                    <p><strong>Please take immediate action to complete this initiative.</strong></p>
                                    
                                    <div style="text-align: center; margin: 30px 0;">
                                        <a href="{PLATFORM_URL}/user/dashboard" style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                                            View Initiative
                                        </a>
                                    </div>
                                    
                                    <p>Best regards,<br>Initiative Platform Team</p>
                                </body>
                                </html>
                                """
                            else:
                                email_body = f"""
                                <html>
                                <body>
                                    <h2 style="color: #ffc107;">📅 Initiative Reminder</h2>
                                    <p>Hello {user_data['name']},</p>
                                    <p>This is a reminder for the following initiative:</p>
                                    
                                    <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                        <h3>{event['title']}</h3>
                                        <p><strong>Description:</strong> {event.get('description', 'N/A')}</p>
                                        <p><strong>Category:</strong> {event.get('category', 'N/A')}</p>
                                        <p><strong>Due Date:</strong> {effective_due_date.strftime('%Y-%m-%d')}</p>
                                        <p><strong>Days Remaining:</strong> {days_until_due} days</p>
                                    </div>
                                    
                                    <div style="text-align: center; margin: 30px 0;">
                                        <a href="{PLATFORM_URL}/user/dashboard" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                                            View Initiative
                                        </a>
                                    </div>
                                    
                                    <p>Best regards,<br>Initiative Platform Team</p>
                                </body>
                                </html>
                                """
                            
                            try:
                                send_email(user_email, subject, email_body)
                                print(f"Reminder email sent to {user_email} for initiative: {event['title']}")
                            except Exception as e:
                                print(f"Failed to send reminder email to {user_email}: {e}")
                
                # Also notify admins about overdue initiatives
                if is_overdue:
                    admin_users = list(db.users.find({'role': 'admin'}))
                    for admin in admin_users:
                        admin_notification = {
                            'type': 'overdue_reminder',
                            'user_email': admin['email'],
                            'event_id': str(event['_id']),
                            'event_title': event['title'],
                            'message': f'Overdue initiative reminder: "{event["title"]}" is {abs(days_until_due)} days overdue',
                            'created_at': datetime.now(),
                            'read': False,
                            'priority': 'high',
                            'assigned_users': event.get('assigned_users', [])
                        }
                        db.notifications.insert_one(admin_notification)
                        
                        # Send email to admin
                        if smtp_settings and smtp_settings.get('enabled', False):
                            admin_subject = f'🚨 ADMIN ALERT: Overdue Initiative - {event["title"]}'
                            admin_email_body = f"""
                            <html>
                            <body>
                                <h2 style="color: #dc3545;">🚨 ADMIN ALERT: Overdue Initiative</h2>
                                <p>Hello Admin,</p>
                                <p>The following initiative is <strong>OVERDUE</strong>:</p>
                                
                                <div style="background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                    <h3>{event['title']}</h3>
                                    <p><strong>Description:</strong> {event.get('description', 'N/A')}</p>
                                    <p><strong>Category:</strong> {event.get('category', 'N/A')}</p>
                                    <p><strong>Due Date:</strong> {effective_due_date.strftime('%Y-%m-%d')}</p>
                                    <p><strong>Days Overdue:</strong> {abs(days_until_due)} days</p>
                                    <p><strong>Assigned Users:</strong> {', '.join(event.get('assigned_users', []))}</p>
                                </div>
                                
                                <div style="text-align: center; margin: 30px 0;">
                                    <a href="{PLATFORM_URL}/admin/dashboard" style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                                        View Dashboard
                                    </a>
                                </div>
                                
                                <p>Best regards,<br>Initiative Platform Team</p>
                            </body>
                            </html>
                            """
                            
                            try:
                                send_email(admin['email'], admin_subject, admin_email_body)
                                print(f"Admin alert email sent to {admin['email']} for overdue initiative: {event['title']}")
                            except Exception as e:
                                print(f"Failed to send admin alert email to {admin['email']}: {e}")
        
        print(f"Reminder check completed at {datetime.now()}")
        
    except Exception as e:
        print(f"Error in send_reminder_notifications: {e}")

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

class User:
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data['name']
        self.designation = user_data.get('designation', 'N/A')
        self.role = user_data['role']
        self.temp_password = user_data.get('temp_password', False)
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
    
    def get_id(self):
        return self.id

@app.route('/')
def index():
    if current_user.is_authenticated:
        # Check if user has temporary password
        user_data = db.users.find_one({'_id': ObjectId(current_user.id)})
        if user_data and user_data.get('temp_password', False) and current_user.role == 'user':
            flash('Please change your temporary password before accessing the dashboard')
            return redirect(url_for('login'))
        
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()  # Convert to lowercase
        password = request.form['password']
        
        print(f"DEBUG: Login attempt for email: {email}")
        
        user_data = db.users.find_one({'email': email})
        
        if user_data:
            print(f"DEBUG: User found: {user_data['name']}, role: {user_data['role']}")
            print(f"DEBUG: temp_password flag: {user_data.get('temp_password', False)}")
            
            if user_data['role'] == 'admin':
                # Admin login
                if email == 'admin@initative.com' and password == 'admin123':
                    user = User(user_data)
                    login_user(user)
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Invalid admin credentials')
            else:
                # User login
                print(f"DEBUG: Password in DB at login: {user_data['password']}")
                print(f"DEBUG: Attempting to verify password: {password}")
                password_check_result = check_password_hash(user_data['password'], password)
                print(f"DEBUG: Password verification result: {password_check_result}")
                
                if password_check_result:
                    print("DEBUG: Password check passed")
                    
                    # Check if user has temporary password
                    if user_data.get('temp_password', False):
                        print("DEBUG: User has temporary password - showing password change form")
                        # Store user info in session for password change
                        session['temp_user_id'] = str(user_data['_id'])
                        session['temp_user_email'] = user_data['email']
                        session['temp_user_name'] = user_data['name']
                        # Stay on login page with password change form
                        return render_template('login.html', show_password_modal=True, user_logged_in=True)
                    else:
                        print("DEBUG: User does not have temporary password - logging in and redirecting to dashboard")
                        user = User(user_data)
                        login_user(user)
                        return redirect(url_for('user_dashboard'))
                else:
                    print("DEBUG: Password check failed")
                    flash('Invalid password')
        else:
            print("DEBUG: User not found")
            flash('User not found')
    
    print("DEBUG: Rendering login.html with no special flags")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        
        # Check if user exists and is active (not a temporary password user)
        user_data = db.users.find_one({'email': email})
        
        if not user_data:
            flash('Email address not found in our system.')
            return render_template('forgot_password.html')
        
        # Previously temp-password users were blocked; now we allow them to reset like others.
        
        # Generate and store OTP
        otp = generate_otp()
        store_otp(email, otp)
        
        # Send OTP email
        smtp_settings = db.smtp_settings.find_one()
        if smtp_settings and smtp_settings.get('enabled', False):
            subject = f'Password Reset OTP - {otp}'
            email_body = f"""
            <html>
            <body>
                <h2 style="color: #007bff;">Password Reset Request</h2>
                <p>Hello {user_data['name']},</p>
                <p>You have requested to reset your password for the Initiative Management Platform.</p>
                
                <div style="background-color: #f8f9fa; border: 2px solid #007bff; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
                    <h3 style="color: #007bff; margin: 0;">Your OTP Code</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 5px; margin: 10px 0;">
                        {otp}
                    </div>
                    <p style="margin: 0; color: #6c757d;">Valid for 10 minutes</p>
                </div>
                
                <p><strong>Important:</strong></p>
                <ul>
                    <li>This OTP is valid for 10 minutes only</li>
                    <li>Do not share this OTP with anyone</li>
                    <li>If you didn't request this, please ignore this email</li>
                </ul>
                
                <p>Best regards,<br>Initiative Platform Team</p>
            </body>
            </html>
            """
            
            try:
                send_email(email, subject, email_body)
                flash(f'OTP has been sent to {email}. Please check your email and enter the 6-digit code.')
                return render_template('forgot_password.html', show_otp_form=True, email=email)
            except Exception as e:
                print(f"Failed to send OTP email: {e}")
                flash('Failed to send OTP email. Please try again or contact your administrator.')
                return render_template('forgot_password.html')
        else:
            flash('Email service is not configured. Please contact your administrator.')
            return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp_route():
    try:
        email = request.form.get('email')
        if email:
            email = email.strip().lower()  # Convert to lowercase for consistency
        otp = request.form.get('otp')
        
        if not email or not otp:
            flash('Email and OTP are required.')
            return render_template('forgot_password.html')
        
        if verify_otp(email, otp):
            # OTP is valid, allow password reset
            session['reset_password_email'] = email  # Store lowercase email in session
            flash('OTP verified successfully. Please enter your new password.')
            return render_template('reset_password.html', email=email)
        else:
            flash('Invalid or expired OTP. Please try again.')
            return render_template('forgot_password.html', show_otp_form=True, email=email)
    except Exception as e:
        print(f"Error in verify_otp_route: {e}")
        flash('An error occurred. Please try again.')
        return render_template('forgot_password.html')

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    try:
        email = request.form.get('email')
        if email:
            email = email.strip().lower()  # Convert to lowercase for consistency
        
        if not email:
            flash('Email is required.')
            return redirect(url_for('forgot_password'))
        
        # Check if user exists and is active
        user_data = db.users.find_one({'email': email})
        
        if not user_data:
            flash('Email address not found in our system.')
            return redirect(url_for('forgot_password'))
        
        # Allow temp-password accounts to receive a new OTP as well.
        
        # Generate and store new OTP
        otp = generate_otp()
        store_otp(email, otp)
        
        # Send new OTP email
        smtp_settings = db.smtp_settings.find_one()
        if smtp_settings and smtp_settings.get('enabled', False):
            subject = f'Password Reset OTP - {otp}'
            email_body = f"""
            <html>
            <body>
                <h2 style="color: #007bff;">Password Reset Request</h2>
                <p>Hello {user_data['name']},</p>
                <p>You have requested a new OTP for password reset.</p>
                
                <div style="background-color: #f8f9fa; border: 2px solid #007bff; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;">
                    <h3 style="color: #007bff; margin: 0;">Your New OTP Code</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 5px; margin: 10px 0;">
                        {otp}
                    </div>
                    <p style="margin: 0; color: #6c757d;">Valid for 10 minutes</p>
                </div>
                
                <p><strong>Important:</strong></p>
                <ul>
                    <li>This OTP is valid for 10 minutes only</li>
                    <li>Do not share this OTP with anyone</li>
                    <li>If you didn't request this, please ignore this email</li>
                </ul>
                
                <p>Best regards,<br>Initiative Platform Team</p>
            </body>
            </html>
            """
            
            try:
                send_email(email, subject, email_body)
                flash(f'New OTP has been sent to {email}. Please check your email.')
                return render_template('forgot_password.html', show_otp_form=True, email=email)
            except Exception as e:
                print(f"Failed to send OTP email: {e}")
                flash('Failed to send OTP email. Please try again or contact your administrator.')
                return render_template('forgot_password.html', show_otp_form=True, email=email)
        else:
            flash('Email service is not configured. Please contact your administrator.')
            return render_template('forgot_password.html', show_otp_form=True, email=email)
    except Exception as e:
        print(f"Error in resend_otp: {e}")
        flash('An error occurred. Please try again.')
        return redirect(url_for('forgot_password'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_password_email' not in session:
        flash('Password reset session expired. Please try again.')
        return redirect(url_for('forgot_password'))
    
    # Normalize email (strip/ lowercase) to ensure matching in DB
    email = session['reset_password_email'].strip().lower()
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        print(f"DEBUG: Resetting password for email: {email}")
        print(f"DEBUG: New password entered: {new_password}")
        print(f"DEBUG: Confirm password entered: {confirm_password}")
        
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', email=email)
        
        if not new_password or len(new_password) < 8:
            flash('Password must be at least 8 characters long.')
            return render_template('reset_password.html', email=email)
        
        # Update password
        try:
            # Hash the new password
            hashed_password = generate_password_hash(new_password)
            print(f"DEBUG: New hashed password for {email}: {hashed_password}")
            
            # Print user found before update
            user_before = db.users.find_one({'email': email})
            print(f"DEBUG: User found before update: {user_before}")
            if not user_before:
                flash('User not found. Please try again.')
                return render_template('reset_password.html', email=email)
            
            # Check if the new password is same as the current one
            if check_password_hash(user_before['password'], new_password):
                flash('New password cannot be the same as the current password.')
                return render_template('reset_password.html', email=email)
            
            # Update the user's password in database
            result = db.users.update_one(
                {'email': email},
                {
                    '$set': {
                        'password': hashed_password,
                        'temp_password': False
                    }
                }
            )
            
            # Treat success if at least one document matched (even if value unchanged)
            if result.modified_count > 0:
                print(f"Password updated successfully for user: {email}")
                
                # Verify the password was actually updated in DB
                updated_user = db.users.find_one({'email': email})
                print(f"DEBUG: Password in DB after update: {updated_user['password']}")
                print(f"DEBUG: Testing password verification: {check_password_hash(updated_user['password'], new_password)}")
                
                # Clear session
                session.pop('reset_password_email', None)
                
                flash('Password reset successfully! You can now login with your new password.')
                return redirect(url_for('login'))
            else:
                print(f"No user found or password not updated for: {email}")
                flash('User not found. Please try again.')
                return render_template('reset_password.html', email=email)
            
        except Exception as e:
            print(f"Error resetting password: {e}")
            flash('Error resetting password. Please try again.')
            return render_template('reset_password.html', email=email)
    
    return render_template('reset_password.html', email=email)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get all users and events
    users = list(db.users.find({'role': 'user'}))
    events = list(db.events.find())
    smtp_settings = db.smtp_settings.find_one()
    
    # Add assigned events count to each user
    for user in users:
        user['assigned_events_count'] = len([e for e in events if user['email'] in e.get('assigned_users', [])])
        user['assigned_events'] = [e for e in events if user['email'] in e.get('assigned_users', [])]
    
    # Calculate detailed statistics
    total_users = len(users)
    total_events = len(events)
    
    # Event status statistics
    pending_events = len([e for e in events if e.get('status') == 'pending'])
    in_progress_events = len([e for e in events if e.get('status') == 'in_progress'])
    delay_events = len([e for e in events if e.get('status') == 'delay'])
    completed_events = len([e for e in events if e.get('status') == 'completed'])
    approved_events = len([e for e in events if e.get('status') == 'approved'])
    
    # User status statistics
    active_users = len([u for u in users if not u.get('temp_password', False)])
    temp_password_users = len([u for u in users if u.get('temp_password', False)])
    
    # Recent activity - last 24 hours only
    from datetime import timedelta
    yesterday = datetime.now() - timedelta(days=1)
    recent_notifications = list(db.notifications.find({
        'created_at': {'$gte': yesterday}
    }).sort('created_at', -1))
    
    # Overdue events (events past due date)
    today = datetime.now().date()
    overdue_events = len([e for e in events if e.get('due_date') and e['due_date'].date() < today and e.get('status') != 'completed'])
    
    stats = {
        'total_users': total_users,
        'total_events': total_events,
        'pending_events': pending_events,
        'in_progress_events': in_progress_events,
        'delay_events': delay_events,
        'completed_events': completed_events,
        'approved_events': approved_events,
        'active_users': active_users,
        'temp_password_users': temp_password_users,
        'overdue_events': overdue_events,
        'recent_notifications': recent_notifications
    }
    
    # Always fetch the latest platform URL from the database
    platform_settings = db.platform_settings.find_one()
    current_platform_url = platform_settings['platform_url'] if platform_settings and platform_settings.get('platform_url') else PLATFORM_URL
    
    return render_template('admin_dashboard.html', users=users, events=events, smtp_settings=smtp_settings, stats=stats, today=today, platform_url=current_platform_url)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].strip().lower()  # Convert to lowercase
        phone = request.form['phone']
        designation = request.form['designation']
        
        # Validate email domain
        if not email.endswith('@sharpandtannan.com'):
            flash('Email address must end with @sharpandtannan.com')
            designations = list(db.designations.find())
            return render_template('create_user.html', designations=designations)
        
        # Check if user already exists
        existing_user = db.users.find_one({'email': email})
        if existing_user:
            flash('User with this email already exists')
            designations = list(db.designations.find())
            return render_template('create_user.html', designations=designations)
        
        # Generate random password
        random_password = generate_random_password()
        
        # Check SMTP settings
        smtp_settings = db.smtp_settings.find_one()
        email_enabled = smtp_settings and smtp_settings.get('enabled', False)
        
        if email_enabled:
            # Send email with password
            email_body = f"""
            Welcome to the Operation Excellence Platform!
            
            Your account has been created successfully.
            Your temporary password is: {random_password}
            
            Please login with this password and you will be prompted to change it.
            
            Platform Link: {PLATFORM_URL}
            
            Best regards,
            Initiative Platform Team
            """
            
            if send_email(email, 'Welcome to Operation Excellence Platform', email_body):
                flash(f'User created successfully. Password sent to {email}')
            else:
                flash(f'User created but email failed. Password: {random_password}')
        else:
            flash(f'User created successfully. Password: {random_password}')
        
        # Create user with temporary password
        user_data = {
            'name': name,
            'email': email,  # Already converted to lowercase
            'phone': phone,
            'designation': designation,
            'password': generate_password_hash(random_password),
            'role': 'user',
            'temp_password': True,
            'created_at': datetime.now()
        }
        
        db.users.insert_one(user_data)
        return redirect(url_for('admin_dashboard'))
    
    designations = list(db.designations.find())
    return render_template('create_user.html', designations=designations)

@app.route('/admin/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        raised_from = request.form['raised_from']
        division = request.form['division']
        due_date = request.form['due_date']
        assigned_users = request.form.getlist('assigned_users')
        
        # Handle custom raised_from input
        if raised_from == 'other':
            custom_raised_from = request.form.get('custom_raised_from', '').strip()
            if custom_raised_from:
                # Check if it already exists in custom_raised_from collection
                existing = db.custom_raised_from.find_one({'name': custom_raised_from})
                if not existing:
                    # Add to custom_raised_from collection
                    raised_from_data = {
                        'name': custom_raised_from,
                        'created_at': datetime.now(),
                        'created_by': current_user.id
                    }
                    db.custom_raised_from.insert_one(raised_from_data)
                raised_from = custom_raised_from
            else:
                flash('Please provide a custom raised from source')
                users = list(db.users.find({'role': 'user'}, {'name': 1, 'email': 1}))
                designations = list(db.designations.find())
                custom_divisions = list(db.custom_divisions.find())
                custom_raised_from_list = list(db.custom_raised_from.find())
                return render_template('create_event.html', users=users, designations=designations, 
                                     custom_divisions=custom_divisions, custom_raised_from=custom_raised_from_list)
        
        # Handle custom division input
        if division == 'others':
            custom_division = request.form.get('custom_division', '').strip()
            if custom_division:
                # Check if it already exists in custom_divisions collection
                existing = db.custom_divisions.find_one({'name': custom_division})
                if not existing:
                    # Add to custom_divisions collection
                    division_data = {
                        'name': custom_division,
                        'created_at': datetime.now(),
                        'created_by': current_user.id
                    }
                    db.custom_divisions.insert_one(division_data)
                division = custom_division
            else:
                flash('Please provide a custom division name')
                users = list(db.users.find({'role': 'user'}, {'name': 1, 'email': 1}))
                designations = list(db.designations.find())
                custom_divisions = list(db.custom_divisions.find())
                custom_raised_from_list = list(db.custom_raised_from.find())
                return render_template('create_event.html', users=users, designations=designations,
                                     custom_divisions=custom_divisions, custom_raised_from=custom_raised_from_list)
        
        # Parse due date
        try:
            due_date = datetime.strptime(due_date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid due date format')
            users = list(db.users.find({'role': 'user'}, {'name': 1, 'email': 1}))
            designations = list(db.designations.find())
            custom_divisions = list(db.custom_divisions.find())
            custom_raised_from_list = list(db.custom_raised_from.find())
            return render_template('create_event.html', users=users, designations=designations,
                                 custom_divisions=custom_divisions, custom_raised_from=custom_raised_from_list)
        
        # Handle file upload
        document_path = None
        if 'document' in request.files:
            file = request.files['document']
            if file and file.filename:
                filename = secure_filename(file.filename)
                if allowed_file(filename):
                    unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    file.save(filepath)
                    document_path = filepath
                else:
                    flash(f'Invalid file type. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}')
                    users = list(db.users.find({'role': 'user'}, {'name': 1, 'email': 1}))
                    designations = list(db.designations.find())
                    custom_divisions = list(db.custom_divisions.find())
                    custom_raised_from_list = list(db.custom_raised_from.find())
                    return render_template('create_event.html', users=users, designations=designations,
                                         custom_divisions=custom_divisions, custom_raised_from=custom_raised_from_list)
        
        # Handle reminders
        reminder_enabled = 'enable_reminders' in request.form
        reminder_days = []
        reminder_times = []
        
        if reminder_enabled:
            # For now we don't collect specific days; backend can use frequency only.
            pass
        
        event_data = {
            'title': title,
            'description': description,
            'category': category,
            'raised_from': raised_from,
            'division': division,
            'due_date': due_date,
            'assigned_users': assigned_users,
            'document_path': document_path,
            'enable_reminders': reminder_enabled,
            'reminder_days': reminder_days,
            'reminder_times': reminder_times,
            'reminder_frequency': request.form.get('reminder_frequency') if reminder_enabled else None,
            'status': 'pending',
            'created_at': datetime.now(),
            'created_by': current_user.id
        }
        
        try:
            result = db.events.insert_one(event_data)
            event_id = str(result.inserted_id)
            
            # Create notifications and send emails for assigned users
            for user_email in assigned_users:
                user = db.users.find_one({'email': user_email})
                if user:
                    notification_data = {
                        'user_email': user_email,
                        'message': f'New initiative assigned: {title}',
                        'type': 'assignment',
                        'event_id': event_id,
                        'read': False,
                        'created_at': datetime.now()
                    }
                    db.notifications.insert_one(notification_data)
                    
                    # Send email notification if SMTP is enabled
                    smtp_settings = db.smtp_settings.find_one()
                    if smtp_settings and smtp_settings.get('enabled', False):
                        email_body = f"""
                        Hello {user['name']},
                        
                        You have been assigned a new initiative:
                        
                        Initiative: {title}
                        Description: {description}
                        Category: {category}
                        Division: {division}
                        Raised From: {raised_from}
                        Due Date: {due_date.strftime('%Y-%m-%d')}
                        
                        Please log in to the Initiative Platform to view the details and start working on this initiative.
                        
                        Platform Link: {PLATFORM_URL}
                        
                        Best regards,
                        Operation Excellence Team
                        """
                        
                        try:
                            send_email(user_email, f'New Initiative Assigned: {title}', email_body)
                            print(f"Assignment email sent to {user_email} for initiative: {title}")
                        except Exception as e:
                            print(f"Failed to send assignment email to {user_email}: {e}")
            
            flash('Initiative created successfully!')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f'Error creating initiative: {str(e)}')
    
    # GET request - show form
    users = list(db.users.find({'role': 'user'}, {'name': 1, 'email': 1}))
    designations = list(db.designations.find())
    custom_divisions = list(db.custom_divisions.find())
    custom_raised_from_list = list(db.custom_raised_from.find())
    return render_template('create_event.html', users=users, designations=designations,
                         custom_divisions=custom_divisions, custom_raised_from=custom_raised_from_list)

@app.route('/admin/smtp_settings', methods=['GET', 'POST'])
@login_required
def smtp_settings():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        enabled = 'enabled' in request.form
        smtp_server = request.form['smtp_server']
        smtp_port = int(request.form['smtp_port'])
        email = request.form['email']
        password = request.form['password']
        
        settings_data = {
            'enabled': enabled,
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'email': email,
            'password': password
        }
        
        db.smtp_settings.update_one({}, {'$set': settings_data}, upsert=True)
        flash('SMTP settings updated successfully')
        return redirect(url_for('admin_dashboard'))
    
    smtp_settings = db.smtp_settings.find_one()
    return render_template('smtp_settings.html', smtp_settings=smtp_settings)

@app.route('/admin/platform_settings', methods=['GET', 'POST'])
@login_required
def platform_settings():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get current platform URL from database or use default
    platform_settings = db.platform_settings.find_one()
    current_platform_url = platform_settings['platform_url'] if platform_settings else PLATFORM_URL
    
    if request.method == 'POST':
        new_platform_url = request.form['platform_url'].strip()
        
        # Validate URL format
        if not new_platform_url.startswith(('http://', 'https://')):
            flash('Platform URL must start with http:// or https://')
            return render_template('platform_settings.html', platform_url=current_platform_url)
        
        # Update the platform URL in the database
        db.platform_settings.update_one({}, {'$set': {'platform_url': new_platform_url}}, upsert=True)
        
        flash('Platform URL updated successfully')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('platform_settings.html', platform_url=current_platform_url)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Check if user has temporary password
    user_data = db.users.find_one({'_id': ObjectId(current_user.id)})
    if user_data and user_data.get('temp_password', False):
        flash('Please change your temporary password before accessing the dashboard')
        return redirect(url_for('login'))
    
    # Get events assigned to this user - separate active and completed
    all_assigned_events = list(db.events.find({'assigned_users': current_user.email}))
    active_events = [event for event in all_assigned_events if event.get('status') != 'completed']
    completed_events = [event for event in all_assigned_events if event.get('status') == 'completed']
    
    # Get user's remarks and files
    user_remarks = list(db.remarks.find({'user_id': current_user.id}))
    
    # Get user's notifications (all unread)
    notifications = list(db.notifications.find({
        'user_email': current_user.email,
        'read': False
    }).sort('created_at', -1))
    
    # Get recent notifications (last 24 hours)
    from datetime import timedelta
    yesterday = datetime.now() - timedelta(days=1)
    recent_notifications = list(db.notifications.find({
        'user_email': current_user.email,
        'created_at': {'$gte': yesterday}
    }).sort('created_at', -1).limit(10))
    
    # Resolve user names in status history for all events and remove duplicates
    for event in active_events + completed_events:
        if event.get('status_history'):
            # Remove duplicate entries from status history
            seen_entries = set()
            unique_history = []
            
            for history_entry in event['status_history']:
                # Create a unique key for each entry
                entry_key = (
                    history_entry.get('status'),
                    history_entry.get('changed_by'),
                    history_entry.get('reason'),
                    history_entry.get('completion_remarks'),
                    history_entry.get('progress_file'),
                    history_entry.get('completion_file'),
                    history_entry.get('revised_due_date')
                )
                
                if entry_key not in seen_entries:
                    seen_entries.add(entry_key)
                    unique_history.append(history_entry)
                else:
                    print(f"Removing duplicate entry for event {event['_id']}: {entry_key}")
            
            # Update the event with deduplicated history
            if len(unique_history) != len(event['status_history']):
                db.events.update_one(
                    {'_id': event['_id']},
                    {'$set': {'status_history': unique_history}}
                )
                event['status_history'] = unique_history
            
            # Resolve user names
            for history_entry in event['status_history']:
                if history_entry.get('changed_by'):
                    # Find the user by ID - handle both ObjectId and string formats
                    try:
                        if isinstance(history_entry['changed_by'], str):
                            user_data = db.users.find_one({'_id': ObjectId(history_entry['changed_by'])})
                        else:
                            user_data = db.users.find_one({'_id': history_entry['changed_by']})
                        
                        if user_data:
                            history_entry['changed_by_name'] = f"{user_data['name']} ({user_data['email']})"
                        else:
                            history_entry['changed_by_name'] = str(history_entry['changed_by'])
                    except Exception as e:
                        print(f"Error resolving user name for {history_entry['changed_by']}: {e}")
                        history_entry['changed_by_name'] = str(history_entry['changed_by'])
                else:
                    history_entry['changed_by_name'] = 'System'
    
    return render_template('user_dashboard.html', 
                         active_events=active_events,
                         completed_events=completed_events,
                         remarks=user_remarks, 
                         notifications=notifications,
                         recent_notifications=recent_notifications,
                         today=datetime.now().date())

@app.route('/user/history')
@login_required
def user_history():
    if current_user.role != 'user':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get completed events assigned to this user
    completed_events = list(db.events.find({
        'assigned_users': current_user.email,
        'status': 'completed'
    }).sort('updated_at', -1))
    
    # Get user's notifications (all unread)
    notifications = list(db.notifications.find({
        'user_email': current_user.email,
        'read': False
    }).sort('created_at', -1))
    
    return render_template('user_history.html', 
                         completed_events=completed_events,
                         notifications=notifications)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if this is a temporary password change
        if 'temp_user_id' in session:
            user_data = db.users.find_one({'_id': ObjectId(session['temp_user_id'])})
            if not user_data:
                flash('User session expired. Please login again.')
                return redirect(url_for('login'))
        else:
            # Regular password change for logged-in users
            if not current_user.is_authenticated:
                flash('Please login first')
                return redirect(url_for('login'))
            user_data = db.users.find_one({'_id': ObjectId(current_user.id)})
        
        if not check_password_hash(user_data['password'], current_password):
            flash('Current password is incorrect')
            if 'temp_user_id' in session:
                return render_template('login.html', show_password_modal=True, user_logged_in=True, error_message='Current password is incorrect')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match')
            if 'temp_user_id' in session:
                return render_template('login.html', show_password_modal=True, user_logged_in=True, error_message='New passwords do not match')
            return render_template('change_password.html')
        
        # Validate password strength
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long')
            if 'temp_user_id' in session:
                return render_template('login.html', show_password_modal=True, user_logged_in=True, error_message='Password must be at least 8 characters long')
            return render_template('change_password.html')
        
        # Update password and remove temp_password flag
        db.users.update_one(
            {'_id': ObjectId(user_data['_id'])},
            {
                '$set': {
                    'password': generate_password_hash(new_password),
                    'temp_password': False
                }
            }
        )
        
        flash('Password changed successfully')
        
        # If this was a temporary password change, log the user in and redirect
        if 'temp_user_id' in session:
            # Clear temporary session data
            temp_user_id = session.pop('temp_user_id', None)
            temp_user_email = session.pop('temp_user_email', None)
            temp_user_name = session.pop('temp_user_name', None)
            
            # Log the user in
            user = User(user_data)
            login_user(user)
            
            return redirect(url_for('user_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    return render_template('change_password.html')

@app.route('/add_remark/<event_id>', methods=['POST'])
@login_required
def add_remark(event_id):
    if current_user.role != 'user':
        flash('Access denied')
        return redirect(url_for('login'))
    
    remark_text = request.form['remark']
    file = request.files.get('file')
    
    remark_data = {
        'event_id': event_id,
        'user_id': current_user.id,
        'user_email': current_user.email,
        'remark': remark_text,
        'file_path': None,
        'created_at': datetime.now()
    }
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{ObjectId()}_{filename}")
        file.save(file_path)
        remark_data['file_path'] = file_path
    
    db.remarks.insert_one(remark_data)
    
    # Get event details for notification
    event_data = db.events.find_one({'_id': ObjectId(event_id)})
    event_title = event_data['title'] if event_data else 'Unknown Event'
    
    # Create detailed notification for admin
    notification_data = {
        'type': 'remark_added',
        'user_id': current_user.id,
        'user_email': current_user.email,
        'user_name': current_user.name,
        'event_id': event_id,
        'event_title': event_title,
        'message': f'New remark added by {current_user.name} for initiative: {event_title}',
        'remark_preview': remark_text[:100] + '...' if len(remark_text) > 100 else remark_text,
        'created_at': datetime.now(),
        'read': False,
        'priority': 'normal'
    }
    db.notifications.insert_one(notification_data)
    
    # Send email notification to admin if SMTP is enabled
    smtp_settings = db.smtp_settings.find_one()
    if smtp_settings and smtp_settings.get('enabled', False):
        admin_users = list(db.users.find({'role': 'admin'}))
        for admin in admin_users:
            email_body = f"""
            Hello Admin,
            
            A new remark has been added to an initiative:
            
            Initiative: {event_title}
            User: {current_user.name} ({current_user.email})
            Remark: {remark_text}
            
            Please log in to the Initiative Platform to review.
            
            Platform Link: {PLATFORM_URL}
            
            Best regards,
            Initiative Platform Team
            """
            
            try:
                send_email(admin['email'], f'New Remark: {event_title}', email_body)
            except Exception as e:
                print(f"Failed to send email to admin {admin['email']}: {e}")
    
    flash('Remark added successfully')
    return redirect(url_for('user_dashboard'))

@app.route('/complete_event/<event_id>', methods=['POST'])
@login_required
def complete_event(event_id):
    if current_user.role != 'user':
        flash('Access denied')
        return redirect(url_for('login'))
    
    db.events.update_one(
        {'_id': ObjectId(event_id)},
        {'$set': {'status': 'completed'}}
    )
    
    flash('Event marked as completed')
    return redirect(url_for('user_dashboard'))

@app.route('/admin/notifications')
@login_required
def admin_notifications():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    notifications = list(db.notifications.find().sort('created_at', -1))
    events = list(db.events.find())
    return render_template('notifications.html', notifications=notifications, events=events)

@app.route('/user/notifications')
@login_required
def user_notifications():
    if current_user.role != 'user':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get all user's notifications
    notifications = list(db.notifications.find({
        'user_email': current_user.email
    }).sort('created_at', -1))
    
    events = list(db.events.find())
    return render_template('user_notifications.html', notifications=notifications, events=events)

@app.route('/user/recent_notifications')
@login_required
def user_recent_notifications():
    if current_user.role != 'user':
        return jsonify({'error': 'Access denied'})
    
    try:
        # Get latest 5 notifications (all time, not just 24 hours)
        recent_notifications = list(db.notifications.find({
            'user_email': current_user.email
        }).sort('created_at', -1).limit(5))
        
        # Count unread notifications
        unread_count = db.notifications.count_documents({
            'user_email': current_user.email,
            'read': False
        })
        
        # Format notifications for JSON response
        formatted_notifications = []
        for notification in recent_notifications:
            formatted_notifications.append({
                '_id': str(notification['_id']),
                'message': notification['message'],
                'type': notification.get('type', 'general'),
                'read': notification.get('read', False),
                'created_at': notification['created_at'].strftime('%Y-%m-%d %H:%M') if notification.get('created_at') else 'N/A'
            })
        
        return jsonify({
            'notifications': formatted_notifications,
            'count': unread_count
        })
    except Exception as e:
        print(f"Error in user_recent_notifications: {e}")
        return jsonify({'error': 'Failed to load notifications'})

@app.route('/admin/recent_notifications')
@login_required
def recent_notifications():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'})
    
    # Get notifications from last 24 hours only
    yesterday = datetime.now() - timedelta(days=1)
    recent_notifications = list(db.notifications.find({
        'created_at': {'$gte': yesterday},
        'read': False
    }).sort('created_at', -1))
    
    # Mark these notifications as read
    notification_ids = [str(n['_id']) for n in recent_notifications]
    if notification_ids:
        db.notifications.update_many(
            {'_id': {'$in': [ObjectId(nid) for nid in notification_ids]}},
            {'$set': {'read': True}}
        )
    
    # Format notifications for dropdown
    formatted_notifications = []
    for notification in recent_notifications:
        formatted_notifications.append({
            'id': str(notification['_id']),
            'message': notification.get('message', ''),
            'user_email': notification.get('user_email', ''),
            'created_at': notification['created_at'].strftime('%Y-%m-%d %H:%M') if notification.get('created_at') else '',
            'type': notification.get('type', 'notification')
        })
    
    return jsonify({
        'notifications': formatted_notifications,
        'count': len(formatted_notifications)
    })

@app.route('/mark_notification_read/<notification_id>')
@login_required
def mark_notification_read(notification_id):
    try:
        # For admin users, they can mark any notification as read
        if current_user.role == 'admin':
            db.notifications.update_one(
                {'_id': ObjectId(notification_id)},
                {'$set': {'read': True}}
            )
        else:
            # For regular users, they can only mark their own notifications as read
            db.notifications.update_one(
                {'_id': ObjectId(notification_id), 'user_email': current_user.email},
                {'$set': {'read': True}}
            )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        if current_user.role == 'admin':
            # Admin can mark all notifications as read
            db.notifications.update_many(
                {'read': False},
                {'$set': {'read': True}}
            )
        else:
            # Regular users can only mark their own notifications as read
            db.notifications.update_many(
                {'user_email': current_user.email, 'read': False},
                {'$set': {'read': True}}
            )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/remove_notification/<notification_id>', methods=['DELETE'])
@login_required
def remove_notification(notification_id):
    try:
        # Find the notification and check if user has access
        notification = db.notifications.find_one({'_id': ObjectId(notification_id)})
        if not notification:
            return jsonify({'success': False, 'error': 'Notification not found'}), 404
        
        # Check if user has permission to remove this notification
        if current_user.role == 'admin':
            # Admin can remove any notification
            db.notifications.delete_one({'_id': ObjectId(notification_id)})
        else:
            # User can only remove their own notifications
            if notification.get('user_email') == current_user.email:
                db.notifications.delete_one({'_id': ObjectId(notification_id)})
            else:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/designation_management')
@login_required
def designation_management():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get designations with user count
    designations = []
    try:
        for designation in db.designations.find():
            user_count = db.users.count_documents({'designation': designation['name']})
            designation['user_count'] = user_count
            designations.append(designation)
    except Exception as e:
        print(f"Error in designation_management: {e}")
        flash('Error loading designations')
    
    return render_template('designation_management.html', designations=designations)

@app.route('/admin/add_designation', methods=['POST'])
@login_required
def add_designation():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    try:
        name = request.form['designation_name']
        description = request.form.get('designation_description', '')
        
        # Check if designation already exists
        existing = db.designations.find_one({'name': name})
        if existing:
            flash('Designation already exists')
            return redirect(url_for('designation_management'))
        
        designation_data = {
            'name': name,
            'description': description,
            'created_at': datetime.now()
        }
        
        db.designations.insert_one(designation_data)
        flash('Designation added successfully')
    except Exception as e:
        print(f"Error adding designation: {e}")
        flash('Error adding designation')
    
    return redirect(url_for('designation_management'))

@app.route('/admin/delete_designation/<designation_id>', methods=['DELETE'])
@login_required
def delete_designation(designation_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        # Check if any users have this designation
        user_count = db.users.count_documents({'designation': designation_id})
        if user_count > 0:
            return jsonify({'success': False, 'error': f'Cannot delete: {user_count} users have this designation'})
        
        db.designations.delete_one({'_id': ObjectId(designation_id)})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/edit_designation/<designation_id>', methods=['POST'])
@login_required
def edit_designation(designation_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        data = request.get_json()
        designation_name = data.get('designation_name', '').strip()
        designation_description = data.get('designation_description', '').strip()
        
        if not designation_name:
            return jsonify({'success': False, 'error': 'Designation name is required'})
        
        # Check if designation name already exists (excluding current designation)
        existing_designation = db.designations.find_one({
            'name': designation_name,
            '_id': {'$ne': ObjectId(designation_id)}
        })
        
        if existing_designation:
            return jsonify({'success': False, 'error': 'Designation name already exists'})
        
        # Update the designation
        update_data = {
            'name': designation_name,
            'description': designation_description
        }
        
        db.designations.update_one(
            {'_id': ObjectId(designation_id)},
            {'$set': update_data}
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    user = db.users.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash('User not found')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].strip().lower()  # Convert to lowercase
        designation = request.form['designation']
        
        # Validate email domain
        if not email.endswith('@sharpandtannan.com'):
            flash('Email address must end with @sharpandtannan.com')
            designations = list(db.designations.find())
            return render_template('edit_user.html', user=user, designations=designations)
        
        # Check if email is already taken by another user
        existing_user = db.users.find_one({'email': email, '_id': {'$ne': ObjectId(user_id)}})
        if existing_user:
            flash('Email address is already taken by another user')
            designations = list(db.designations.find())
            return render_template('edit_user.html', user=user, designations=designations)
        
        # Update user data
        update_data = {
            'name': name,
            'email': email,  # Already converted to lowercase
            'designation': designation
        }
        
        # If password is provided, update it
        if request.form.get('new_password'):
            new_password = request.form['new_password']
            update_data['password'] = generate_password_hash(new_password)
            update_data['temp_password'] = True
            
            # Send email with new password if SMTP is enabled
            smtp_settings = db.smtp_settings.find_one()
            if smtp_settings and smtp_settings.get('enabled', False):
                email_body = f"""
                Your password has been updated by an administrator.
                
                Your new temporary password is: {new_password}
                
                Please login with this password and you will be prompted to change it.
                
                Best regards,
                Initiative Platform Team
                """
                
                if send_email(email, 'Password Updated - Initiative Platform', email_body):
                    flash(f'User updated successfully. New password sent to {email}')
                else:
                    flash(f'User updated but email failed. New password: {new_password}')
            else:
                flash(f'User updated successfully. New password: {new_password}')
        else:
            flash('User updated successfully')
        
        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        return redirect(url_for('admin_dashboard'))
    
    designations = list(db.designations.find())
    return render_template('edit_user.html', user=user, designations=designations)

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found')
            return redirect(url_for('admin_dashboard'))
        
        # Check if user has any assigned events and remove them
        assigned_events = list(db.events.find({'assigned_users': user['email']}))
        if assigned_events:
            # Remove user from all assigned events
            for event in assigned_events:
                db.events.update_one(
                    {'_id': event['_id']},
                    {'$pull': {'assigned_users': user['email']}}
                )
            
            # Create notification about user removal from events
            for event in assigned_events:
                notification = {
                    'type': 'user_removed_from_event',
                    'message': f'User "{user["name"]}" has been removed from initiative "{event["title"]}" due to account deletion',
                    'user_email': current_user.email,
                    'event_id': str(event['_id']),
                    'event_title': event['title'],
                    'removed_user': user['name'],
                    'created_at': datetime.now(),
                    'read': False
                }
                db.notifications.insert_one(notification)
            
            flash(f'User deleted successfully. Removed from {len(assigned_events)} assigned initiative(s).')
        else:
            flash('User deleted successfully')
        
        # Delete user's remarks and notifications
        db.remarks.delete_many({'user_id': user_id})
        db.notifications.delete_many({'user_email': user['email']})
        
        # Delete the user
        db.users.delete_one({'_id': ObjectId(user_id)})
        flash('User deleted successfully')
        
    except Exception as e:
        flash(f'Error deleting user: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/generate_temp_password/<user_id>', methods=['POST'])
@login_required
def generate_temp_password(user_id):
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    try:
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found')
            return redirect(url_for('admin_dashboard'))
        
        # Generate new temporary password
        new_temp_password = generate_random_password()
        
        # Update user with new temporary password
        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {
                '$set': {
                    'password': generate_password_hash(new_temp_password),
                    'temp_password': True
                }
            }
        )
        
        # Send email with new password if SMTP is enabled
        smtp_settings = db.smtp_settings.find_one()
        if smtp_settings and smtp_settings.get('enabled', False):
            email_body = f"""
            Your password has been reset by an administrator.
            
            Your new temporary password is: {new_temp_password}
            
            Please login with this password and you will be prompted to change it.
            
            Platform Link: {PLATFORM_URL}
            
            Best regards,
            Initiative Platform Team
            """
            
            if send_email(user['email'], 'Password Reset - Initiative Platform', email_body):
                flash(f'Temporary password generated and sent to {user["email"]}')
            else:
                flash(f'Temporary password generated but email failed. Password: {new_temp_password}')
        else:
            flash(f'Temporary password generated: {new_temp_password}')
        
    except Exception as e:
        flash(f'Error generating temporary password: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/update_event_status/<event_id>', methods=['POST'])
@login_required
def update_event_status(event_id):
    if current_user.role != 'user':
        flash('Access denied')
        return redirect(url_for('login'))
    
    status = request.form['status']
    reason = request.form.get('reason', '')
    completion_remarks = request.form.get('completion_remarks', '')
    revised_due_date = request.form.get('revised_due_date', '')
    completion_file = request.files.get('completion_file')
    progress_file = request.files.get('progress_file')
    
    # Get current event data
    event = db.events.find_one({'_id': ObjectId(event_id)})
    if not event:
        flash('Event not found')
        return redirect(url_for('user_dashboard'))
    
    # Prepare status history entry
    status_history_entry = {
        'status': status,
        'changed_by': current_user.id,
        'changed_at': datetime.now(),
        'reason': reason if reason else 'Status updated',
        'previous_status': event.get('status', 'unknown')
    }
    
    # Only preserve documents that are relevant to this status change
    # Don't preserve all existing documents as it creates confusion
    # Each status history entry should only contain documents relevant to that specific change
    
    update_data = {
        'status': status,
        'updated_at': datetime.now(),
        'updated_by': current_user.id
    }
    
    # Add completion remarks if provided
    if completion_remarks:
        update_data['completion_remarks'] = completion_remarks
        status_history_entry['completion_remarks'] = completion_remarks
    
    # Handle due date changes
    if revised_due_date:
        revised_date = datetime.strptime(revised_due_date, '%Y-%m-%d')
        update_data['revised_due_date'] = revised_date
        status_history_entry['revised_due_date'] = revised_date
        status_history_entry['previous_due_date'] = event.get('due_date')
        
        # Notify all other assigned users about the due date change
        for user_email in event.get('assigned_users', []):
            if user_email != current_user.email:  # Don't notify the user who made the change
                user_data = db.users.find_one({'email': user_email})
                user_name = user_data['name'] if user_data else user_email
                
                due_date_notification = {
                    'type': 'due_date_revised',
                    'message': f'Due date for initiative "{event["title"]}" has been revised to {revised_due_date}',
                    'user_email': user_email,
                    'user_name': user_name,
                    'event_id': event_id,
                    'event_title': event['title'],
                    'previous_due_date': event.get('due_date'),
                    'new_due_date': revised_date,
                    'revised_by': current_user.name,
                    'reason': reason if reason else 'Due date revised',
                    'created_at': datetime.now(),
                    'read': False,
                    'priority': 'high'
                }
                db.notifications.insert_one(due_date_notification)
                
                # Send email notification if SMTP is enabled
                smtp_settings = db.smtp_settings.find_one()
                if smtp_settings and smtp_settings.get('enabled', False):
                    email_body = f"""
                    Hello {user_name},
                    
                    The due date for initiative "{event['title']}" has been revised:
                    
                    Initiative: {event['title']}
                    Previous Due Date: {event.get('due_date').strftime('%Y-%m-%d') if event.get('due_date') else 'N/A'}
                    New Due Date: {revised_due_date}
                    Revised By: {current_user.name}
                    Reason: {reason if reason else 'Due date revised'}
                    
                    Please log in to the Initiative Platform to view the updated details.
                    
                    Platform Link: {PLATFORM_URL}
                    
                    Best regards,
                    Initiative Platform Team
                    """
                    
                    try:
                        send_email(user_email, f'Due Date Revised: {event["title"]}', email_body)
                    except Exception as e:
                        print(f"Failed to send email to {user_email}: {e}")
    
    # Handle progress file upload (for in_progress and delay statuses)
    if progress_file and progress_file.filename:
        if allowed_file(progress_file.filename):
            filename = secure_filename(progress_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"progress_{event_id}_{filename}")
            progress_file.save(file_path)
            update_data['progress_file'] = file_path
            status_history_entry['progress_file'] = file_path
    
    # Handle completion file upload
    if completion_file and completion_file.filename:
        if allowed_file(completion_file.filename):
            filename = secure_filename(completion_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"completion_{event_id}_{filename}")
            completion_file.save(file_path)
            update_data['completion_file'] = file_path
            status_history_entry['completion_file'] = file_path
    
    # Update event with new data and add to status history
    # Check if this status change is different from the last one to avoid duplicates
    current_event = db.events.find_one({'_id': ObjectId(event_id)})
    if current_event and current_event.get('status_history'):
        last_history = current_event['status_history'][-1]
        
        # Check if this is a true duplicate by comparing key fields
        is_duplicate = (
            last_history.get('status') == status and
            last_history.get('changed_by') == current_user.id and
            # Check if the last entry was made within the last 5 minutes (to catch rapid duplicates)
            (datetime.now() - last_history.get('changed_at', datetime.now())).total_seconds() < 300
        )
        
        # Additional checks for specific status types
        if status == 'completed':
            # For completed status, also check if completion_remarks and completion_file are the same
            is_duplicate = is_duplicate and (
                last_history.get('completion_remarks') == completion_remarks and
                last_history.get('completion_file') == status_history_entry.get('completion_file')
            )
        elif status in ['in_progress', 'delay']:
            # For progress/delay status, check if reason and progress_file are the same
            is_duplicate = is_duplicate and (
                last_history.get('reason') == reason and
                last_history.get('progress_file') == status_history_entry.get('progress_file')
            )
        
        if not is_duplicate:
            db.events.update_one(
                {'_id': ObjectId(event_id)}, 
                {
                    '$set': update_data,
                    '$push': {'status_history': status_history_entry}
                }
            )
        else:
            # Just update the event data without adding duplicate history
            db.events.update_one(
                {'_id': ObjectId(event_id)}, 
                {'$set': update_data}
            )
    else:
        # No existing history, add the first entry
        db.events.update_one(
            {'_id': ObjectId(event_id)}, 
            {
                '$set': update_data,
                '$push': {'status_history': status_history_entry}
            }
        )
    
    # Create detailed notification for admin
    status_display_names = {
        'pending': 'Pending',
        'in_progress': 'Work in Progress',
        'delay': 'Delay',
        'completed': 'Complete'
    }
    
    notification_message = f'Initiative "{event["title"]}" status changed from {status_display_names.get(event.get("status", "unknown"), event.get("status", "unknown"))} to {status_display_names.get(status, status)}'
    if revised_due_date:
        notification_message += f' - Due date revised to {revised_due_date}'
    if status in ['in_progress', 'delay'] and reason:
        notification_message += f' - Details: {reason[:100]}{"..." if len(reason) > 100 else ""}'
    if status == 'completed' and completion_remarks:
        notification_message += f' - Remarks: {completion_remarks[:100]}{"..." if len(completion_remarks) > 100 else ""}'
    
    notification = {
        'type': 'status_changed',
        'message': notification_message,
        'user_email': current_user.email,
        'user_name': current_user.name,
        'event_id': event_id,
        'event_title': event['title'],
        'previous_status': event.get('status', 'unknown'),
        'new_status': status,
        'reason': reason if reason else 'No reason provided',
        'completion_remarks': completion_remarks if completion_remarks else '',
        'created_at': datetime.now(),
        'read': False,
        'priority': 'high' if status in ['completed', 'overdue', 'delay'] else 'normal'
    }
    db.notifications.insert_one(notification)
    
    # Send email notification to admin if SMTP is enabled
    smtp_settings = db.smtp_settings.find_one()
    if smtp_settings and smtp_settings.get('enabled', False):
        admin_users = list(db.users.find({'role': 'admin'}))
        for admin in admin_users:
            status_display_names = {
                'pending': 'Pending',
                'in_progress': 'Work in Progress',
                'delay': 'Delay',
                'completed': 'Complete'
            }
            
            email_body = f"""
            Hello Admin,
            
            Initiative status has been updated:
            
            Initiative: {event['title']}
            User: {current_user.name} ({current_user.email})
            Previous Status: {status_display_names.get(event.get('status', 'unknown'), event.get('status', 'unknown'))}
            New Status: {status_display_names.get(status, status)}
            Reason: {reason if reason else 'No reason provided'}
            """
            
            if revised_due_date:
                email_body += f"Due Date Revised: {revised_due_date}\n"
            
            if status in ['in_progress', 'delay'] and reason:
                email_body += f"Progress/Delay Details: {reason}\n"
            
            if status == 'completed' and completion_remarks:
                email_body += f"Completion Remarks: {completion_remarks}\n"
            
            email_body += f"""
            Please log in to the Initiative Platform to review.
            
            Platform Link: {PLATFORM_URL}
            
            Best regards,
            Initiative Platform Team
            """
            
            try:
                send_email(admin['email'], f'Initiative Status Update: {event["title"]}', email_body)
            except Exception as e:
                print(f"Failed to send email to admin {admin['email']}: {e}")
    
    flash('Event status updated successfully')
    return redirect(url_for('user_dashboard'))

@app.route('/admin/user_status_view')
@login_required
def user_status_view():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get filter parameters
    selected_user = request.args.get('user')
    selected_event = request.args.get('event')
    selected_status = request.args.get('status')
    
    users = list(db.users.find({'role': 'user'}))
    events = list(db.events.find())
    remarks = list(db.remarks.find())
    
    # Filter users
    if selected_user:
        users = [u for u in users if str(u['_id']) == selected_user]
    
    # Filter events
    if selected_event:
        events = [e for e in events if str(e['_id']) == selected_event]
    
    # Filter by status (on events)
    if selected_status:
        events = [e for e in events if e.get('status') == selected_status]
    
    # For dropdowns
    all_users = list(db.users.find({'role': 'user'}))
    all_events = list(db.events.find())
    all_statuses = ['pending', 'in_progress', 'delay', 'completed']
    
    # Get all users for name lookup in status history
    all_users_for_lookup = list(db.users.find())
    
    # Resolve user names in status history for all events and remove duplicates
    for event in events:
        if event.get('status_history'):
            # Remove duplicate entries from status history
            seen_entries = set()
            unique_history = []
            
            for history_entry in event['status_history']:
                # Create a unique key for each entry
                entry_key = (
                    history_entry.get('status'),
                    history_entry.get('changed_by'),
                    history_entry.get('reason'),
                    history_entry.get('completion_remarks'),
                    history_entry.get('progress_file'),
                    history_entry.get('completion_file'),
                    history_entry.get('revised_due_date')
                )
                
                if entry_key not in seen_entries:
                    seen_entries.add(entry_key)
                    unique_history.append(history_entry)
                else:
                    print(f"Removing duplicate entry for event {event['_id']}: {entry_key}")
            
            # Update the event with deduplicated history
            if len(unique_history) != len(event['status_history']):
                db.events.update_one(
                    {'_id': event['_id']},
                    {'$set': {'status_history': unique_history}}
                )
                event['status_history'] = unique_history
            
            # Resolve user names
            for history_entry in event['status_history']:
                if history_entry.get('changed_by'):
                    # Find the user by ID - handle both ObjectId and string formats
                    try:
                        if isinstance(history_entry['changed_by'], str):
                            user_data = db.users.find_one({'_id': ObjectId(history_entry['changed_by'])})
                        else:
                            user_data = db.users.find_one({'_id': history_entry['changed_by']})
                        
                        if user_data:
                            history_entry['changed_by_name'] = f"{user_data['name']} ({user_data['email']})"
                        else:
                            history_entry['changed_by_name'] = str(history_entry['changed_by'])
                    except Exception as e:
                        print(f"Error resolving user name for {history_entry['changed_by']}: {e}")
                        history_entry['changed_by_name'] = str(history_entry['changed_by'])
                else:
                    history_entry['changed_by_name'] = 'System'
    
    # Get today's date for overdue comparison
    today = datetime.now().date()
    
    return render_template(
        'user_status_view.html',
        users=users,
        events=events,
        remarks=remarks,
        all_users=all_users,
        all_events=all_events,
        all_statuses=all_statuses,
        selected_user=selected_user,
        selected_event=selected_event,
        selected_status=selected_status,
        today=today,
        all_users_for_lookup=all_users_for_lookup
    )

@app.route('/admin/edit_event/<event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    event = db.events.find_one({'_id': ObjectId(event_id)})
    if not event:
        flash('Event not found')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        raised_from = request.form['raised_from']
        division = request.form['division']
        due_date = request.form['due_date']
        assigned_users = request.form.getlist('assigned_users')
        
        # Handle custom raised_from input
        if raised_from == 'other':
            custom_raised_from = request.form.get('custom_raised_from', '').strip()
            if custom_raised_from:
                # Check if this custom raised_from already exists
                existing_rf = db.custom_raised_from.find_one({'name': custom_raised_from})
                if not existing_rf:
                    # Add new custom raised_from to collection
                    db.custom_raised_from.insert_one({
                        'name': custom_raised_from,
                        'created_at': datetime.now(),
                        'created_by': current_user.id
                    })
                raised_from = custom_raised_from
            else:
                flash('Please provide a custom raised from source.')
                users = list(db.users.find({'role': 'user', 'email': {'$regex': '@sharpandtannan\\.com$'}}))
                custom_raised_from = list(db.custom_raised_from.find())
                custom_divisions = list(db.custom_divisions.find())
                return render_template('edit_event.html', event=event, users=users, custom_raised_from=custom_raised_from, custom_divisions=custom_divisions)
        
        # Handle custom division input
        if division == 'others':
            custom_division = request.form.get('custom_division', '').strip()
            if custom_division:
                # Check if this custom division already exists
                existing_div = db.custom_divisions.find_one({'name': custom_division})
                if not existing_div:
                    # Add new custom division to collection
                    db.custom_divisions.insert_one({
                        'name': custom_division,
                        'created_at': datetime.now(),
                        'created_by': current_user.id
                    })
                division = custom_division
            else:
                flash('Please provide a custom division name.')
                users = list(db.users.find({'role': 'user', 'email': {'$regex': '@sharpandtannan\\.com$'}}))
                custom_raised_from = list(db.custom_raised_from.find())
                custom_divisions = list(db.custom_divisions.find())
                return render_template('edit_event.html', event=event, users=users, custom_raised_from=custom_raised_from, custom_divisions=custom_divisions)
        
        # Handle document upload
        document_path = event.get('document_path')  # Keep existing document if no new one uploaded
        if 'document' in request.files:
            file = request.files['document']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                new_document_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{ObjectId()}_{filename}")
                file.save(new_document_path)
                # Delete old file if it exists and is different
                if document_path and os.path.exists(document_path) and document_path != new_document_path:
                    try:
                        os.remove(document_path)
                    except Exception as e:
                        print(f"DEBUG: Could not delete old document: {e}")
                document_path = new_document_path
        
        update_data = {
            'title': title,
            'description': description,
            'category': category,
            'raised_from': raised_from,
            'division': division,
            'due_date': datetime.strptime(due_date, '%Y-%m-%d'),
            'assigned_users': assigned_users,
            'document_path': document_path,
            'updated_at': datetime.now(),
            'updated_by': current_user.id,
            'enable_reminders': 'enable_reminders' in request.form,
            'reminder_frequency': request.form.get('reminder_frequency', 'weekly') if 'enable_reminders' in request.form else None
        }
        
        # Get previous assigned users to detect new assignments
        previous_assigned_users = event.get('assigned_users', [])
        newly_assigned_users = [user for user in assigned_users if user not in previous_assigned_users]
        
        db.events.update_one({'_id': ObjectId(event_id)}, {'$set': update_data})
        
        # Create notifications for all assigned users about the event update
        for user_email in assigned_users:
            user_data = db.users.find_one({'email': user_email})
            user_name = user_data['name'] if user_data else user_email
            
            # Determine notification type and message
            if user_email in newly_assigned_users:
                notification_type = 'assignment'
                notification_message = f'New initiative assigned: {title}'
            else:
                notification_type = 'event_updated'
                notification_message = f'Initiative "{title}" has been updated by admin'
            
            notification = {
                'type': notification_type,
                'message': notification_message,
                'user_email': user_email,
                'user_name': user_name,
                'event_id': event_id,
                'event_title': title,
                'updated_by': current_user.email,
                'created_at': datetime.now(),
                'read': False,
                'priority': 'normal'
            }
            db.notifications.insert_one(notification)
            
            # Send email notification if SMTP is enabled
            smtp_settings = db.smtp_settings.find_one()
            if smtp_settings and smtp_settings.get('enabled', False):
                if user_email in newly_assigned_users:
                    # Send assignment email for newly assigned users
                    email_body = f"""
                    Hello {user_name},
                    
                    You have been assigned a new initiative:
                    
                    Initiative: {title}
                    Description: {description}
                    Category: {category}
                    Division: {division}
                    Raised From: {raised_from}
                    Due Date: {due_date}
                    
                    Please log in to the Initiative Platform to view the details and start working on this initiative.
                    
                    Platform Link: {PLATFORM_URL}
                    
                    Best regards,
                    Operation Excellence Team
                    """
                    email_subject = f'New Initiative Assigned: {title}'
                else:
                    # Send update email for existing users
                    email_body = f"""
                    Hello {user_name},
                    
                    The initiative "{title}" has been updated by admin:
                    
                    Initiative: {title}
                    Description: {description}
                    Category: {category}
                    Division: {division}
                    Raised From: {raised_from}
                    Due Date: {due_date}
                    
                    Please log in to the Initiative Platform to view the updated details.
                    
                    Platform Link: {PLATFORM_URL}
                    
                    Best regards,
                    Operation Excellence Team
                    """
                    email_subject = f'Initiative Updated: {title}'
                
                try:
                    send_email(user_email, email_subject, email_body)
                    if user_email in newly_assigned_users:
                        print(f"Assignment email sent to {user_email} for initiative: {title}")
                    else:
                        print(f"Update email sent to {user_email} for initiative: {title}")
                except Exception as e:
                    print(f"Failed to send email to {user_email}: {e}")
        
        flash('Initiative updated successfully')
        return redirect(url_for('admin_dashboard'))
    
    # GET request - show form with existing data
    users = list(db.users.find({'role': 'user'}, {'name': 1, 'email': 1}))
    designations = list(db.designations.find())
    custom_divisions = list(db.custom_divisions.find())
    custom_raised_from_list = list(db.custom_raised_from.find())
    return render_template('edit_event.html', event=event, users=users, designations=designations,
                         custom_divisions=custom_divisions, custom_raised_from=custom_raised_from_list)

@app.route('/admin/delete_event/<event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    event = db.events.find_one({'_id': ObjectId(event_id)})
    if not event:
        flash('Event not found')
        return redirect(url_for('admin_dashboard'))
    
    # Create notifications for all assigned users about the event deletion
    for user_email in event.get('assigned_users', []):
        user_data = db.users.find_one({'email': user_email})
        user_name = user_data['name'] if user_data else user_email
        
        notification = {
            'type': 'event_deleted',
            'message': f'Initiative "{event["title"]}" has been deleted by admin',
            'user_email': user_email,
            'user_name': user_name,
            'event_id': event_id,
            'event_title': event['title'],
            'deleted_by': current_user.email,
            'created_at': datetime.now(),
            'read': False,
            'priority': 'high'
        }
        db.notifications.insert_one(notification)
        
        # Send email notification if SMTP is enabled
        smtp_settings = db.smtp_settings.find_one()
        if smtp_settings and smtp_settings.get('enabled', False):
            email_body = f"""
            Hello {user_name},
            
            The initiative "{event['title']}" has been deleted by admin.
            
            Initiative: {event['title']}
            Description: {event.get('description', 'N/A')}
            
            This initiative is no longer active.
            
            Platform Link: {PLATFORM_URL}
            
            Best regards,
            Initiative Platform Team
            """
            
            try:
                send_email(user_email, f'Initiative Deleted: {event["title"]}', email_body)
            except Exception as e:
                print(f"Failed to send email to {user_email}: {e}")
    
    # Delete the event
    db.events.delete_one({'_id': ObjectId(event_id)})
    
    # Delete related notifications (but keep the deletion notifications we just created)
    db.notifications.delete_many({'event_id': event_id, 'type': {'$ne': 'event_deleted'}})
    
    # Delete related remarks
    db.remarks.delete_many({'event_id': event_id})
    
    flash(f'Initiative "{event["title"]}" deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/download_file/<path:filename>')
@login_required
def download_file(filename):
    """Serve uploaded files for download"""
    try:
        print(f"DEBUG: Download request for filename: {filename}")

        # Normalize filename: remove any leading uploads/ or backslashes
        filename = filename.replace("\\", "/")
        if filename.startswith("uploads/"):
            filename = filename[len("uploads/"):]
        filename = filename.split("/")[-1]  # just the file name

        print(f"DEBUG: Normalized filename: {filename}")

        uploads_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
        file_path = os.path.join(uploads_dir, filename)
        print(f"DEBUG: Full file path: {file_path}")

        if os.path.exists(file_path):
            print(f"DEBUG: File exists, serving: {file_path}")
            return send_file(file_path, as_attachment=True)
        else:
            print(f"DEBUG: File not found at: {file_path}")
            flash('File not found')
            if current_user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
    except Exception as e:
        print(f"DEBUG: Download error: {str(e)}")
        flash(f'Error downloading file: {str(e)}')
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

@app.route('/admin/system_health')
@login_required
def system_health():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get system health information
    db_info = get_db_connection_info()
    
    # Get basic statistics
    try:
        total_users = db.users.count_documents({})
        total_events = db.events.count_documents({})
        total_notifications = db.notifications.count_documents({})
        active_sessions = len(session) if session else 0
    except Exception as e:
        total_users = total_events = total_notifications = active_sessions = 0
        print(f"Error getting statistics: {e}")
    
    health_info = {
        'database': db_info,
        'statistics': {
            'total_users': total_users,
            'total_events': total_events,
            'total_notifications': total_notifications,
            'active_sessions': active_sessions
        },
        'system': {
            'platform_url': PLATFORM_URL,
            'max_content_length': MAX_CONTENT_LENGTH,
            'session_timeout': SESSION_TIMEOUT,
            'max_concurrent_users': MAX_CONCURRENT_USERS
        }
    }
    
    return render_template('system_health.html', health_info=health_info)

@app.route('/admin/send_overdue_reminders')
@login_required
def send_overdue_reminders():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Manually trigger reminder notifications
    send_reminder_notifications()
    flash('Reminder notifications sent successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/trigger_reminders')
@login_required
def trigger_reminders():
    """API endpoint to trigger reminders (can be called by cron job)"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        send_reminder_notifications()
        return jsonify({'success': True, 'message': 'Reminders triggered successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Create admin user if not exists
def create_admin_user():
    try:
        admin_email = 'admin@initative.com'  # Define admin email
        admin_user = db.users.find_one({'email': admin_email})
        if not admin_user:
            admin_data = {
                'name': 'Admin',
                'email': admin_email,
                'password': generate_password_hash('admin123'),
                'role': 'admin',
                'temp_password': False,
                'created_at': datetime.now()
            }
            db.users.insert_one(admin_data)
            print("✅ Admin user created successfully!")
        else:
            print("✅ Admin user already exists!")
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")

def load_platform_settings():
    """Load platform settings from database on startup"""
    global PLATFORM_URL
    try:
        platform_settings = db.platform_settings.find_one()
        if platform_settings and platform_settings.get('platform_url'):
            PLATFORM_URL = platform_settings['platform_url']
            print(f"✅ Platform URL loaded from database: {PLATFORM_URL}")
        else:
            print(f"✅ Using default platform URL: {PLATFORM_URL}")
    except Exception as e:
        print(f"❌ Error loading platform settings: {e}")

# Background reminder scheduler
def start_reminder_scheduler():
    """Start background thread for automatic reminders"""
    import threading
    import schedule
    
    def run_reminders():
        try:
            send_reminder_notifications()
        except Exception as e:
            print(f"Error in reminder scheduler: {e}")
    
    # Schedule reminders to run daily at 9:00 AM
    schedule.every().day.at("09:00").do(run_reminders)
    
    def scheduler_thread():
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    # Start scheduler in background thread
    scheduler_thread = threading.Thread(target=scheduler_thread, daemon=True)
    scheduler_thread.start()
    print("✅ Reminder scheduler started (daily at 9:00 AM)")

# Create admin user and load settings when app starts
create_admin_user()
load_platform_settings()

# Start the reminder scheduler
try:
    start_reminder_scheduler()
except Exception as e:
    print(f"❌ Error starting reminder scheduler: {e}")

# Custom Division Management Routes
@app.route('/admin/custom_divisions')
@login_required
def custom_divisions():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get custom divisions with usage count
    custom_divisions = []
    try:
        for division in db.custom_divisions.find():
            usage_count = db.events.count_documents({'division': division['name']})
            division['usage_count'] = usage_count
            custom_divisions.append(division)
    except Exception as e:
        print(f"Error in custom_divisions: {e}")
        flash('Error loading custom divisions')
    
    return render_template('custom_divisions.html', custom_divisions=custom_divisions)

@app.route('/admin/add_custom_division', methods=['POST'])
@login_required
def add_custom_division():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        data = request.get_json()
        division_name = data.get('division_name', '').strip()
        
        if not division_name:
            return jsonify({'success': False, 'error': 'Division name is required'})
        
        # Check if division already exists
        existing = db.custom_divisions.find_one({'name': division_name})
        if existing:
            return jsonify({'success': False, 'error': 'Division already exists'})
        
        division_data = {
            'name': division_name,
            'created_at': datetime.now(),
            'created_by': current_user.id
        }
        
        result = db.custom_divisions.insert_one(division_data)
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/edit_custom_division/<division_id>', methods=['POST'])
@login_required
def edit_custom_division(division_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        data = request.get_json()
        division_name = data.get('division_name', '').strip()
        
        if not division_name:
            return jsonify({'success': False, 'error': 'Division name is required'})
        
        # Check if division name already exists (excluding current division)
        existing_division = db.custom_divisions.find_one({
            'name': division_name,
            '_id': {'$ne': ObjectId(division_id)}
        })
        
        if existing_division:
            return jsonify({'success': False, 'error': 'Division name already exists'})
        
        # Get old division name for updating events
        old_division = db.custom_divisions.find_one({'_id': ObjectId(division_id)})
        old_name = old_division['name'] if old_division else None
        
        # Update the division
        db.custom_divisions.update_one(
            {'_id': ObjectId(division_id)},
            {'$set': {'name': division_name}}
        )
        
        # Update all events that use this division
        if old_name and old_name != division_name:
            db.events.update_many(
                {'division': old_name},
                {'$set': {'division': division_name}}
            )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_custom_division/<division_id>', methods=['DELETE'])
@login_required
def delete_custom_division(division_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        # Get division details
        division = db.custom_divisions.find_one({'_id': ObjectId(division_id)})
        if not division:
            return jsonify({'success': False, 'error': 'Division not found'})
        
        # Check if any events use this division
        usage_count = db.events.count_documents({'division': division['name']})
        if usage_count > 0:
            return jsonify({'success': False, 'error': f'Cannot delete: {usage_count} event(s) use this division'})
        
        db.custom_divisions.delete_one({'_id': ObjectId(division_id)})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Custom Raised From Management Routes
@app.route('/admin/custom_raised_from')
@login_required
def custom_raised_from():
    if current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('login'))
    
    # Get custom raised from with usage count
    custom_raised_from = []
    try:
        for raised_from in db.custom_raised_from.find():
            usage_count = db.events.count_documents({'raised_from': raised_from['name']})
            raised_from['usage_count'] = usage_count
            custom_raised_from.append(raised_from)
    except Exception as e:
        print(f"Error in custom_raised_from: {e}")
        flash('Error loading custom raised from')
    
    return render_template('custom_raised_from.html', custom_raised_from=custom_raised_from)

@app.route('/admin/add_custom_raised_from', methods=['POST'])
@login_required
def add_custom_raised_from():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        data = request.get_json()
        raised_from_name = data.get('raised_from_name', '').strip()
        
        if not raised_from_name:
            return jsonify({'success': False, 'error': 'Raised from name is required'})
        
        # Check if raised from already exists
        existing = db.custom_raised_from.find_one({'name': raised_from_name})
        if existing:
            return jsonify({'success': False, 'error': 'Raised from source already exists'})
        
        raised_from_data = {
            'name': raised_from_name,
            'created_at': datetime.now(),
            'created_by': current_user.id
        }
        
        result = db.custom_raised_from.insert_one(raised_from_data)
        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/edit_custom_raised_from/<raised_from_id>', methods=['POST'])
@login_required
def edit_custom_raised_from(raised_from_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        data = request.get_json()
        raised_from_name = data.get('raised_from_name', '').strip()
        
        if not raised_from_name:
            return jsonify({'success': False, 'error': 'Raised from name is required'})
        
        # Check if raised from name already exists (excluding current one)
        existing_raised_from = db.custom_raised_from.find_one({
            'name': raised_from_name,
            '_id': {'$ne': ObjectId(raised_from_id)}
        })
        
        if existing_raised_from:
            return jsonify({'success': False, 'error': 'Raised from name already exists'})
        
        # Get old raised from name for updating events
        old_raised_from = db.custom_raised_from.find_one({'_id': ObjectId(raised_from_id)})
        old_name = old_raised_from['name'] if old_raised_from else None
        
        # Update the raised from
        db.custom_raised_from.update_one(
            {'_id': ObjectId(raised_from_id)},
            {'$set': {'name': raised_from_name}}
        )
        
        # Update all events that use this raised from
        if old_name and old_name != raised_from_name:
            db.events.update_many(
                {'raised_from': old_name},
                {'$set': {'raised_from': raised_from_name}}
            )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_custom_raised_from/<raised_from_id>', methods=['DELETE'])
@login_required
def delete_custom_raised_from(raised_from_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        # Get raised from details
        raised_from = db.custom_raised_from.find_one({'_id': ObjectId(raised_from_id)})
        if not raised_from:
            return jsonify({'success': False, 'error': 'Raised from not found'})
        
        # Check if any events use this raised from
        usage_count = db.events.count_documents({'raised_from': raised_from['name']})
        if usage_count > 0:
            return jsonify({'success': False, 'error': f'Cannot delete: {usage_count} event(s) use this raised from source'})
        
        db.custom_raised_from.delete_one({'_id': ObjectId(raised_from_id)})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # Test password hashing functionality
    print("Testing password hashing...")
    test_password_hashing()
    
    app.run(debug=True, host='0.0.0.0', port=80) 