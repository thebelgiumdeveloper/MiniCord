from dataclasses import dataclass
from typing import Optional
from datetime import timedelta, datetime, UTC
from uuid import uuid4

@dataclass
class User:
  id: str
  username: str
  email_hash: str
  password: str
  salt: bytes
  age: Optional[ bytes ] = None

  @classmethod
  def create_new( cls, username: str, password_hash: str, email_hash: str,
                  salt: bytes, encrypted_age: Optional[ bytes ] = None ) -> 'User':
    return cls(
      id=str( uuid4( ) ),
      username=username,
      password=password_hash,
      email_hash=email_hash,
      salt=salt,
      age=encrypted_age
    )


@dataclass
class EmailVerification:
  user_id: str
  token_hash: str
  expires_at: int

  @classmethod
  def create( cls, user_id: str, token_hash: str, expires_hours: int = 24 ) -> 'EmailVerification':
    expires_at = int( (datetime.now( UTC ) + timedelta( hours=expires_hours )).timestamp( ) )
    return cls( user_id=user_id, token_hash=token_hash, expires_at=expires_at )

  def is_expired( self ) -> bool:
    return datetime.now( UTC ).timestamp( ) > self.expires_at