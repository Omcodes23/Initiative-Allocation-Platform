#!/usr/bin/env python3
"""
Script to create admin user in MongoDB
"""

import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

def create_admin_user():
    try:
        # MongoDB Configuration
        mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
        print(f"Connecting to MongoDB: {mongo_uri}")
        
        client = MongoClient(mongo_uri)
        db = client.get_database()
        
        # Test connection
        client.admin.command('ping')
        print("✅ MongoDB connection successful!")
        
        # Check if admin user exists
        admin_user = db.users.find_one({'email': 'admin@initative.com'})
        
        if not admin_user:
            admin_data = {
                'name': 'Admin',
                'email': 'admin@initative.com',
                'password': generate_password_hash('admin123'),
                'role': 'admin',
                'temp_password': False,
                'created_at': datetime.now()
            }
            
            result = db.users.insert_one(admin_data)
            print(f"✅ Admin user created successfully! ID: {result.inserted_id}")
        else:
            print("✅ Admin user already exists!")
            print(f"   Email: {admin_user['email']}")
            print(f"   Name: {admin_user['name']}")
            print(f"   Role: {admin_user['role']}")
        
        # List all users
        users = list(db.users.find())
        print(f"\n📊 Total users in database: {len(users)}")
        for user in users:
            print(f"   - {user['email']} ({user['role']})")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    print("=" * 50)
    print("Creating Admin User")
    print("=" * 50)
    create_admin_user()
    print("=" * 50) 