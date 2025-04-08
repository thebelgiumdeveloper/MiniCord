from fastapi import FastAPI, Request, Response, HTTPException
import sqlite3
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import bcrypt
from uuid import uuid4
import jwt
from datetime import datetime, timedelta

load_dotenv()
app = FastAPI()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_value(value, password: str, salt: bytes) -> bytes:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    if isinstance(value, int):
        value_bytes = str(value).encode('utf-8')
    else:
        value_bytes = value.encode('utf-8')
    encrypted = aesgcm.encrypt(nonce, value_bytes, None)
    return nonce + encrypted

def decrypt_value(encrypted_data: bytes, password: str, salt: bytes, return_int=False) -> str | int:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    decrypted = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    return int(decrypted) if return_int else decrypted

# This should not be pushed to production. This is for tests only !
@app.get('/create_db')
async def create_db(request: Request):
    if os.getenv('ADMIN_SECRET') is None:
        return Response(status_code=404)

    if request.headers.get('Authorization') == os.getenv('ADMIN_SECRET') and request.headers.get('User-Agent') == os.getenv('USER_AGENT'):
        with sqlite3.connect('minicord.db') as connection:
            cursor = connection.cursor()

            cursor.execute('''CREATE TABLE IF NOT EXISTS Users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email_hash TEXT NOT NULL,  -- Changed to TEXT for hashed email
                age BLOB,
                salt BLOB NOT NULL
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS Preferences (
                user_id TEXT PRIMARY KEY,
                theme TEXT DEFAULT 'dark',
                notifications INTEGER DEFAULT 1,
                language TEXT DEFAULT 'en',
                custom_css TEXT,
                FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS EmailVerifications (
                user_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,  -- Unix timestamp
                FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
            )''')

            connection.commit()

        return {'success': True, 'message': 'Created Database'}
    else:
        return Response(status_code=404)

@app.get('/')
async def root():
    return {'message': 'Hello World'}

@app.get('/hello/{name}')
async def say_hello(name: str):
    return {'message': f'Hello {name}'}

@app.post('/auth/login')
async def login(request: Request):
    json = await request.json()
    username = json.get('username')
    email = json.get('email')
    password = json.get('password')

    if not (username or email) or not password:
        return {'success': False, 'error': 'fields_missing', 'message': 'Missing or empty fields'}

    try:
        with sqlite3.connect('minicord.db') as connection:
            cursor = connection.cursor()

            user = None
            if username:
                cursor.execute('SELECT id, username, password, email_hash, salt FROM Users WHERE username = ?', (username,))
                user = cursor.fetchone()
            else:
                email_hash = bcrypt.hashpw(email.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute('SELECT id, username, password, email_hash, salt FROM Users WHERE email_hash = ?', (email_hash,))
                user = cursor.fetchone()

            if not user or not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                return {'success': False, 'error': 'invalid_credentials', 'message': f'Invalid {'username' if username else 'email'} or password'}

            user_id = user[0]
            jwt_secret = os.getenv('JWT_SECRET')
            if not jwt_secret:
                raise ValueError('JWT_SECRET not set in .env')

            token = jwt.encode(
                {
                    'user_id': user_id,
                    'exp': datetime.now(datetime.UTC) + timedelta(minutes=15)
                },
                jwt_secret,
                algorithm='HS256'
            )

        return {'success': True, 'message': 'Successfully logged in', 'token': token}

    except Exception as e:
        return {'success': False, 'error': 'login_error', 'message': f'Error: {str(e)}'}

@app.post('/auth/register')
async def register(request: Request):
    json = await request.json()
    username = json.get('username')
    password = json.get('password')
    email = json.get('email')
    age = json.get('age')

    if not all([username, password, email is not None]):
        return {'success': False, 'error': 'fields_missing', 'message': 'Missing or empty fields'}

    user_id = str(uuid4())
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    email_hash = bcrypt.hashpw(email.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    salt = os.urandom(16)
    encrypted_age = encrypt_value(age, password, salt) if age is not None else None

    try:
        with sqlite3.connect('minicord.db') as connection:
            cursor = connection.cursor()

            cursor.execute('''
                    INSERT INTO Users (id, username, password, email_hash, age, salt) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, username, hashed_password, email_hash, encrypted_age, salt))

            cursor.execute('''
                    INSERT INTO Preferences (user_id) 
                    VALUES (?)
                ''', (user_id,))

            # Generate email verification token
            verification_token = os.urandom(32).hex()
            token_hash = bcrypt.hashpw(verification_token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            expires_at = int((datetime.now(datetime.UTC) + timedelta(hours=24)).timestamp())
            cursor.execute('''
                    INSERT INTO EmailVerifications (user_id, token_hash, expires_at)
                    VALUES (?, ?, ?)
                ''', (user_id, token_hash, expires_at))

            connection.commit()

        return {'success': True, 'message': 'Successfully registered', 'user_id': user_id, 'verification_token': verification_token}

    except sqlite3.IntegrityError as e:
        return {'success': False, 'error': 'duplicate_username', 'message': 'Username already exists'}
    except Exception as e:
        return {'success': False, 'error': 'database_error', 'message': f'Error: {str(e)}'}

@app.post('/auth/verify_email')
async def verify_email(request: Request):
    json = await request.json()
    user_id = json.get('user_id')
    token = json.get('token')

    if not all([user_id, token]):
        return {'success': False, 'error': 'fields_missing', 'message': 'Missing user_id or token'}

    try:
        with sqlite3.connect('minicord.db') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT token_hash, expires_at FROM EmailVerifications WHERE user_id = ?', (user_id,))
            verification = cursor.fetchone()

            if not verification or datetime.now(datetime.UTC).timestamp() > verification[1]:
                return {'success': False, 'error': 'invalid_or_expired_token', 'message': 'Invalid or expired verification token'}

            if not bcrypt.checkpw(token.encode('utf-8'), verification[0].encode('utf-8')):
                return {'success': False, 'error': 'invalid_token', 'message': 'Invalid verification token'}

            cursor.execute('DELETE FROM EmailVerifications WHERE user_id = ?', (user_id,))
            connection.commit()

        return {'success': True, 'message': 'Email verified successfully'}

    except Exception as e:
        return {'success': False, 'error': 'verification_error', 'message': f'Error: {str(e)}'}

@app.post('/auth/update_password')
async def update_password(request: Request):
    json = await request.json()
    username = json.get('username')
    old_password = json.get('old_password')
    new_password = json.get('new_password')

    if not all([username, old_password, new_password]):
        return {'success': False, 'error': 'fields_missing', 'message': 'Missing or empty fields'}

    try:
        with sqlite3.connect('minicord.db') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT id, password, age, salt FROM Users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if not user or not bcrypt.checkpw(old_password.encode('utf-8'), user[1].encode('utf-8')):
                return {'success': False, 'error': 'invalid_credentials', 'message': 'Invalid username or password'}

            user_id, _, encrypted_age, salt = user
            age = decrypt_value(encrypted_age, old_password, salt, return_int=True) if encrypted_age else None

            new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            new_encrypted_age = encrypt_value(age, new_password, salt) if age is not None else None

            cursor.execute('''
                UPDATE Users 
                SET password = ?, age = ?
                WHERE id = ?
            ''', (new_hashed_password, new_encrypted_age, user_id))

            connection.commit()

        return {'success': True, 'message': 'Password updated successfully'}

    except Exception as e:
        return {'success': False, 'error': 'database_error', 'message': f'Error: {str(e)}'}

@app.post('/auth/request_reset')
async def request_reset(request: Request):
    json = await request.json()
    username = json.get('username')
    email = json.get('email')

    if not all([username, email]):
        return {'success': False, 'error': 'fields_missing', 'message': 'Missing fields'}

    try:
        with sqlite3.connect('minicord.db') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT id, email_hash FROM Users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if not user or not bcrypt.checkpw(email.encode('utf-8'), user[1].encode('utf-8')):
                return {'success': False, 'error': 'invalid_credentials', 'message': 'Invalid username or email'}

            user_id = user[0]
            reset_token = os.urandom(32).hex()
            token_hash = bcrypt.hashpw(reset_token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            expires_at = int((datetime.now(datetime.UTC) + timedelta(hours=1)).timestamp())

            cursor.execute('''
                INSERT OR REPLACE INTO EmailVerifications (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token_hash, expires_at))
            connection.commit()

            # Here, you'd integrate an SMTP service to send reset_token to email
            # For now, return it to the client to handle
            return {'success': True, 'message': 'Reset token generated', 'reset_token': reset_token}

    except Exception as e:
        return {'success': False, 'error': 'reset_error', 'message': f'Error: {str(e)}'}

@app.get('/protected')
async def protected_route(request: Request):
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        raise HTTPException(401, 'Invalid token')
    token = auth.split(' ')[1]
    try:
        payload = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])
        return {'user_id': payload['user_id']}
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, 'Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(401, 'Invalid token')