# Platform Configuration Guide

## How to Update Platform URL

### Method 1: Environment Variable (Recommended)
1. Create a `.env` file in the project root
2. Add the following line:
   ```
   PLATFORM_URL=https://your-domain.com
   ```
3. Restart the application

### Method 2: Admin Dashboard (Easiest)
1. Login as admin
2. Go to Admin Dashboard
3. Click the gear icon (⚙️) next to the platform URL
4. Update the URL in the form
5. Click "Update Platform URL"

### Method 3: Direct Configuration File
1. Edit `config.py`
2. Update the `PLATFORM_URL` variable
3. Restart the application

## Configuration Options

### Platform URL Examples:
- **Local Development**: `http://localhost:9000`
- **Production HTTPS**: `https://your-domain.com`
- **Custom Port**: `http://localhost:8080`
- **Subdomain**: `https://initiative.yourcompany.com`

### Environment Variables:
```bash
# Platform Configuration
PLATFORM_URL=https://your-domain.com

# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/

# Flask Configuration
SECRET_KEY=your-secret-key-here
DEBUG=False

# Email Configuration
DEFAULT_EMAIL_SENDER=noreply@initiative.com
```

## Important Notes:
- ✅ Changes take effect immediately
- ✅ All email notifications will use the new URL
- ✅ Admin dashboard will show the updated URL
- ✅ URL must start with `http://` or `https://`
- ✅ For production, always use HTTPS URLs

## Troubleshooting:
- If the URL doesn't update, restart the application
- Check that the URL format is correct (must include protocol)
- Ensure the URL is accessible to all users
- For production, make sure the domain is properly configured 