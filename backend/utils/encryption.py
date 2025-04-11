import os
import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Union, Tuple


def derive_key( password: str, salt: bytes ) -> bytes:
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256( ),
    length=32,
    salt=salt,
    iterations=100000,
  )
  return kdf.derive( password.encode( 'utf-8' ) )


def encrypt_value( value: Union[ str, int ], password: str, salt: bytes ) -> bytes:
  key = derive_key( password, salt )
  aesgcm = AESGCM( key )
  nonce = os.urandom( 12 )

  if isinstance( value, int ):
    value_bytes = str( value ).encode( 'utf-8' )
  else:
    value_bytes = value.encode( 'utf-8' )

  encrypted = aesgcm.encrypt( nonce, value_bytes, None )
  return nonce + encrypted


def decrypt_value( encrypted_data: bytes, password: str, salt: bytes, return_int=False ) -> Union[ str, int ]:
  key = derive_key( password, salt )
  aesgcm = AESGCM( key )
  nonce = encrypted_data[ :12 ]
  ciphertext = encrypted_data[ 12: ]
  decrypted = aesgcm.decrypt( nonce, ciphertext, None ).decode( 'utf-8' )
  return int( decrypted ) if return_int else decrypted


def hash_password( password: str ) -> str:
  return bcrypt.hashpw( password.encode( 'utf-8' ), bcrypt.gensalt( ) ).decode( 'utf-8' )


def check_password( password: str, hashed_password: str ) -> bool:
  return bcrypt.checkpw( password.encode( 'utf-8' ), hashed_password.encode( 'utf-8' ) )


def hash_email( email: str ) -> str:
  return bcrypt.hashpw( email.encode( 'utf-8' ), bcrypt.gensalt( ) ).decode( 'utf-8' )


def check_email( email: str, hashed_email: str ) -> bool:
  return bcrypt.checkpw( email.encode( 'utf-8' ), hashed_email.encode( 'utf-8' ) )


def generate_token( ) -> Tuple[ str, str ]:
  token = os.urandom( 32 ).hex( )
  token_hash = bcrypt.hashpw( token.encode( 'utf-8' ), bcrypt.gensalt( ) ).decode( 'utf-8' )
  return token, token_hash


def verify_token( token: str, token_hash: str ) -> bool:
  return bcrypt.checkpw( token.encode( 'utf-8' ), token_hash.encode( 'utf-8' ) )