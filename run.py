#!/usr/bin/env python3
"""
Initiative Management Platform Startup Script
"""

import os
import sys
from app import app

if __name__ == '__main__':
    print("=" * 50)
    print("Initiative Management Platform")
    print("=" * 50)
    print("Starting the application...")
    print("Access the application at: http://localhost:80")
    print("Admin Login:")
    print("  Email: admin@initative.com")
    print("  Password: admin123")
    print("=" * 50)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=80)
    except KeyboardInterrupt:
        print("\nApplication stopped by user.")
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1) 