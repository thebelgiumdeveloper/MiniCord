import jwt
from datetime import datetime, timedelta, UTC
import os
from uuid import uuid4
from typing import Optional, Dict, Tuple, Any

from ..config import Config
from ..utils.encryption import (
  hash_password, check_password, hash_email, check_email,
  encrypt_value, decrypt_value, generate_token, verify_token
)
from ..models.user import User, EmailVerification
from ..database import get_db_connection
from ..services.email_service import EmailService

class AuthService:

  @staticmethod
  def register_user( username: str, password: str, email: str,
                     age: Optional[ int ] = None ) -> Tuple[ bool, Dict[ str, Any ] ]:
    try:
      hashed_password = hash_password( password )
      email_hash = hash_email( email )

      salt = os.urandom( 16 )
      encrypted_age = encrypt_value( age, password, salt ) if age is not None else None

      user = User.create_new(
        username=username,
        password_hash=hashed_password,
        email_hash=email_hash,
        salt=salt,
        encrypted_age=encrypted_age
      )

      verification_token, token_hash = generate_token( )
      verification = EmailVerification.create(
        user_id=user.id,
        token_hash=token_hash,
        expires_hours=Config.EMAIL_VERIFICATION_HOURS
      )

      with get_db_connection( ) as connection:
        cursor = connection.cursor( )

        cursor.execute(
          '''INSERT INTO Users (id, username, password, email_hash, age, salt) 
          VALUES (?, ?, ?, ?, ?, ?)''',
          (user.id, user.username, user.password, user.email_hash, user.age, user.salt)
        )

        cursor.execute(
          '''INSERT INTO Preferences (user_id) VALUES (?)''',
          (user.id,)
        )

        cursor.execute(
          '''INSERT INTO EmailVerifications (user_id, token_hash, expires_at)
          VALUES (?, ?, ?)''',
          (verification.user_id, verification.token_hash, verification.expires_at)
        )

        connection.commit( )

      print( f'register_user: {email}' )
      EmailService.send_verification_email( email, user.id, verification_token )

      return True, {
        'message': 'Successfully registered. Please check your email for verification instructions.',
        'user_id': user.id
      }

    except Exception as e:
      return False, {
        'error': 'registration_error',
        'message': f'Error: {str( e )}'
      }

  @staticmethod
  def login( username: Optional[ str ] = None, email: Optional[ str ] = None,
             password: str = None ) -> Tuple[ bool, Dict[ str, Any ] ]:
    try:
      if not (username or email) or not password:
        return False, {
          'error': 'fields_missing',
          'message': 'Missing or empty fields'
        }

      with get_db_connection( ) as connection:
        cursor = connection.cursor( )

        user = None
        if username:
          cursor.execute(
            'SELECT id, username, password, email_hash, salt FROM Users WHERE username = ?',
            (username,)
          )
          user = cursor.fetchone( )
        else:
          # Hash email for comparison
          email_hash = hash_email( email )
          cursor.execute(
            'SELECT id, username, password, email_hash, salt FROM Users WHERE email_hash = ?',
            (email_hash,)
          )
          user = cursor.fetchone( )

        if not user or not check_password( password, user[ 2 ] ):
          return False, {
            'error': 'invalid_credentials',
            'message': f'Invalid {"username" if username else "email"} or password'
          }

        # Generate JWT token
        user_id = user[ 0 ]
        token = jwt.encode(
          {
            'user_id': user_id,
            'exp': datetime.now( UTC ) + timedelta( minutes=Config.JWT_EXPIRATION_MINUTES )
          },
          Config.JWT_SECRET,
          algorithm='HS256'
        )

        return True, {
          'message': 'Successfully logged in',
          'token': token
        }

    except Exception as e:
      return False, {
        'error': 'login_error',
        'message': f'Error: {str( e )}'
      }

  @staticmethod
  def verify_email( user_id: str, token: str ) -> Tuple[ bool, Dict[ str, str ] ]:
    try:
      with get_db_connection( ) as connection:
        cursor = connection.cursor( )
        cursor.execute(
          'SELECT token_hash, expires_at FROM EmailVerifications WHERE user_id = ?',
          (user_id,)
        )
        verification = cursor.fetchone( )

        if not verification:
          return False, {
            'error': 'invalid_token',
            'message': 'Invalid verification token'
          }

        token_hash, expires_at = verification

        if datetime.now( UTC ).timestamp( ) > expires_at:
          return False, {
            'error': 'expired_token',
            'message': 'Verification token has expired'
          }

        if not verify_token( token, token_hash ):
          return False, {
            'error': 'invalid_token',
            'message': 'Invalid verification token'
          }

        cursor.execute( 'DELETE FROM EmailVerifications WHERE user_id = ?', (user_id,) )
        connection.commit( )

        return True, { 'message': 'Email verified successfully' }

    except Exception as e:
      return False, {
        'error': 'verification_error',
        'message': f'Error: {str( e )}'
      }

  @staticmethod
  def update_password( username: str, old_password: str, new_password: str ) -> Tuple[ bool, Dict[ str, str ] ]:
    try:
      with get_db_connection( ) as connection:
        cursor = connection.cursor( )
        cursor.execute(
          'SELECT id, password, age, salt FROM Users WHERE username = ?',
          (username,)
        )
        user = cursor.fetchone( )

        if not user or not check_password( old_password, user[ 1 ] ):
          return False, {
            'error': 'invalid_credentials',
            'message': 'Invalid username or password'
          }

        user_id, _, encrypted_age, salt = user

        age = None
        if encrypted_age:
          age = decrypt_value( encrypted_age, old_password, salt, return_int=True )

        new_hashed_password = hash_password( new_password )
        new_encrypted_age = encrypt_value( age, new_password, salt ) if age is not None else None

        cursor.execute(
          '''UPDATE Users 
          SET password = ?, age = ?
          WHERE id = ?''',
          (new_hashed_password, new_encrypted_age, user_id)
        )
        connection.commit( )

        return True, { 'message': 'Password updated successfully' }

    except Exception as e:
      return False, {
        'error': 'update_error',
        'message': f'Error: {str( e )}'
      }

  @staticmethod
  def request_password_reset( username: str, email: str ) -> Tuple[ bool, Dict[ str, Any ] ]:
    try:
      with get_db_connection( ) as connection:
        cursor = connection.cursor( )
        cursor.execute(
          'SELECT id, email_hash FROM Users WHERE username = ?',
          (username,)
        )
        user = cursor.fetchone( )

        if not user or not check_email( email, user[ 1 ] ):
          return False, {
            'error': 'invalid_credentials',
            'message': 'Invalid username or email'
          }

        user_id = user[ 0 ]
        reset_token, token_hash = generate_token( )

        expires_at = int( (datetime.now( UTC ) +
                           timedelta( hours=Config.PASSWORD_RESET_HOURS )).timestamp( ) )

        cursor.execute(
          '''INSERT OR REPLACE INTO EmailVerifications (user_id, token_hash, expires_at)
          VALUES (?, ?, ?)''',
          (user_id, token_hash, expires_at)
        )
        connection.commit( )

        email_sent = EmailService.send_password_reset_email( email, user_id, reset_token )

        if email_sent:
          return True, {
            'message': 'Password reset instructions sent to your email'
          }
        else:
          return True, {
            'message': 'Password reset requested. Check your email for instructions.',
            'reset_token': reset_token  # Only for development, remove in production
          }

    except Exception as e:
      return False, {
        'error': 'reset_error',
        'message': f'Error: {str( e )}'
      }

  @staticmethod
  def verify_jwt_token( token: str ) -> Tuple[ bool, Dict[ str, Any ] ]:
    try:
      payload = jwt.decode( token, Config.JWT_SECRET, algorithms=[ 'HS256' ] )
      return True, payload
    except jwt.ExpiredSignatureError:
      return False, { 'error': 'token_expired', 'message': 'Token has expired' }
    except jwt.InvalidTokenError:
      return False, { 'error': 'invalid_token', 'message': 'Invalid token' }