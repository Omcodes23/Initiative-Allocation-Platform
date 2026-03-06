#!/usr/bin/env python3
"""
Test script to verify password hashing functionality using Werkzeug's secure password management features.
"""

from werkzeug.security import generate_password_hash, check_password_hash

def test_password_hashing():
    """Test password hashing and verification"""
    test_password = "test123456"
    
    print("=== Password Hashing Test ===")
    print(f"Original password: {test_password}")
    
    # Generate hash with default method
    hashed = generate_password_hash(test_password)
    print(f"Default generated hash: {hashed}")
    
    # Verify using original password
    verification_result = check_password_hash(hashed, test_password)
    print(f"Verification result (default): {verification_result}")
    
    # Test with wrong password
    wrong_password = "wrongpassword"
    wrong_verification = check_password_hash(hashed, wrong_password)
    print(f"Wrong password verification: {wrong_verification}")
    
    # Generate SHA256 hash
    hashed_sha256 = generate_password_hash(test_password, method='sha256')
    print(f"SHA256 generated hash: {hashed_sha256}")
    
    # Verify using SHA256 hash
    sha256_verification = check_password_hash(hashed_sha256, test_password)
    print(f"SHA256 verification result: {sha256_verification}")
    
    print("=== Test Complete ===")
    return verification_result and sha256_verification

if __name__ == "__main__":
    success = test_password_hashing()
    if success:
        print("✅ All password hashing tests passed!")
    else:
        print("❌ Some password hashing tests failed!")