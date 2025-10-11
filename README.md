# Initiative Management Platform

A comprehensive Flask-based platform for managing initiatives, events, and user assignments with email notifications and file upload capabilities.

## Features

### Admin Features
- **User Management**: Create users with random passwords
- **Event Management**: Create and assign events to users
- **SMTP Configuration**: Configure email settings for password delivery
- **Notifications**: View user activity and remarks
- **Dashboard**: Overview of users, events, and system status

### User Features
- **Event Assignment**: View assigned events
- **Remarks**: Add comments and upload files to events
- **Event Completion**: Mark events as completed
- **Password Management**: Change temporary passwords

### Email Integration
- **Automatic Password Delivery**: Send random passwords via email when SMTP is enabled
- **Fallback Display**: Show passwords on screen when email is disabled
- **SMTP Configuration**: Easy setup for Gmail, Outlook, and other providers

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: MongoDB
- **Authentication**: Flask-Login
- **Frontend**: Bootstrap 5, Font Awesome
- **Email**: SMTP integration
- **File Upload**: Secure file handling

## Installation

### Prerequisites

1. **Python 3.7+**
2. **MongoDB** (running on localhost:27017)
3. **pip** (Python package manager)

### Setup Instructions

1. **Clone or download the project**
   ```bash
   cd initative
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start MongoDB**
   - Make sure MongoDB is running on `localhost:27017`
   - The application will automatically create the database and collections

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   - Open your browser and go to `http://localhost:9000`
   - Login with admin credentials:
     - Email: `admin@initative.com`
     - Password: `admin123`

## Usage Guide

### Admin Workflow

1. **Login as Admin**
   - Use the provided admin credentials
   - Access the admin dashboard

2. **Configure SMTP (Optional)**
   - Go to "SMTP Settings"
   - Enable email service
   - Configure your email provider settings
   - For Gmail: Use App Password if 2FA is enabled

3. **Create Users**
   - Go to "Create User"
   - Enter name and email
   - System generates random password
   - Password is sent via email (if SMTP enabled) or displayed on screen

4. **Create Events**
   - Go to "Create Event"
   - Enter event title and description
   - Select users to assign
   - Events are automatically assigned to selected users

5. **Monitor Activity**
   - Check "Notifications" for user activity
   - View remarks and file uploads
   - Track event completion status

### User Workflow

1. **First Login**
   - Use the random password provided by admin
   - System prompts to change password
   - Set a new secure password

2. **View Assigned Events**
   - Dashboard shows all assigned events
   - See event status (Active/Completed)

3. **Add Remarks**
   - Click "Add Remark" on any active event
   - Enter comments and optionally upload files
   - Admin receives notification

4. **Complete Events**
   - Click "Complete" button when finished
   - Event status changes to completed

## File Structure

```
initative/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/            # HTML templates
│   ├── base.html         # Base template with navigation
│   ├── login.html        # Login page
│   ├── admin_dashboard.html
│   ├── create_user.html
│   ├── create_event.html
│   ├── smtp_settings.html
│   ├── user_dashboard.html
│   ├── change_password.html
│   └── notifications.html
└── uploads/              # File upload directory (created automatically)
```

## Database Collections

- **users**: User accounts and authentication
- **events**: Event definitions and assignments
- **remarks**: User remarks and file uploads
- **notifications**: Admin notifications
- **smtp_settings**: Email configuration

## Security Features

- **Password Hashing**: All passwords are securely hashed
- **File Upload Security**: Restricted file types and secure naming
- **Session Management**: Flask-Login for secure sessions
- **Input Validation**: Form validation and sanitization

## Email Configuration

### Gmail Setup
1. Enable 2-Factor Authentication
2. Generate App Password
3. Use App Password in SMTP settings
4. Server: `smtp.gmail.com`
5. Port: `587`

### Outlook Setup
1. Server: `smtp-mail.outlook.com`
2. Port: `587`
3. Use your regular password

## Troubleshooting

### Common Issues

1. **MongoDB Connection Error**
   - Ensure MongoDB is running
   - Check if port 27017 is available

2. **Email Not Sending**
   - Verify SMTP settings
   - Check email provider requirements
   - For Gmail: Use App Password, not regular password

3. **File Upload Issues**
   - Check uploads directory permissions
   - Verify file type is allowed

4. **Login Issues**
   - Verify admin credentials
   - Check if user exists in database

## Development

### Adding New Features
1. Add routes in `app.py`
2. Create corresponding templates
3. Update navigation in `base.html`
4. Test thoroughly

### Database Modifications
- The application uses MongoDB with automatic collection creation
- No manual database setup required

## License

This project is created for educational and demonstration purposes.

## Support

For issues or questions, please check the troubleshooting section above or review the code comments for implementation details. 