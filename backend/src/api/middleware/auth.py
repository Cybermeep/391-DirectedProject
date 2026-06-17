"""
Authentication middleware for the NIDS API.

This module provides JWT-based authentication and role-based
access control for the API endpoints.
"""

from functools import wraps
from flask import request, jsonify
import jwt
import os
from datetime import datetime, timedelta
import hashlib

# Simple in-memory user store (replace with database in production)
USERS = {
    'admin': {
        'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
        'role': 'admin'
    },
    'viewer': {
        'password_hash': hashlib.sha256('viewer123'.encode()).hexdigest(),
        'role': 'viewer'
    }
}

SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

def generate_token(username, role):
    """
    Generate a JWT token for a user.
    
    Args:
        username (str): Username
        role (str): User role (admin, viewer)
        
    Returns:
        str: JWT token
    """
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """
    Verify and decode a JWT token.
    
    Args:
        token (str): JWT token
        
    Returns:
        dict: Decoded payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require authentication for routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is required'}), 401
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401
        
        # Add user info to request context
        request.user = payload
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user') or request.user.get('role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    
    return decorated

# Login endpoint (to be added to main app)
def login():
    """Authenticate user and return token."""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    if username not in USERS:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    user = USERS[username]
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if user['password_hash'] != password_hash:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    token = generate_token(username, user['role'])
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'username': username,
            'role': user['role']
        }
    })