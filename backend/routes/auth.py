from fastapi import APIRouter, Request, HTTPException, Depends
from typing import Dict, Any

from ..config import Config
from ..services.auth_service import AuthService

router = APIRouter( prefix="/auth", tags=[ "authentication" ] )

@router.post( "/login" )
async def login( request: Request ) -> Dict[ str, Any ]:
  json = await request.json( )
  username = json.get( 'username' )
  email = json.get( 'email' )
  password = json.get( 'password' )

  success, response = AuthService.login( username, email, password )
  if not success:
    return { 'success': False, **response }

  return { 'success': True, **response }

@router.post( "/register" )
async def register( request: Request ) -> Dict[ str, Any ]:
  json = await request.json( )
  username = json.get( 'username' )
  password = json.get( 'password' )
  email = json.get( 'email' )
  age = json.get( 'age' )

  if not all( [ username, password, email is not None ] ):
    return {
      'success': False,
      'error': 'fields_missing',
      'message': 'Missing or empty fields'
    }

  print(f'register_route: {email}')
  success, response = AuthService.register_user( username, password, email, age )

  # In development mode, we might want to include the verification token in the response
  # In production, this should be removed
  if success and Config.EMAIL_ENABLED is False and 'verification_token' in response:
    # Only return the token if email sending is disabled (development mode)
    return { 'success': success, **response }
  elif 'verification_token' in response:
    # Remove token from response in production
    del response[ 'verification_token' ]

  return { 'success': success, **response }


@router.post( "/request_reset" )
async def request_reset( request: Request ) -> Dict[ str, Any ]:
  json = await request.json( )
  username = json.get( 'username' )
  email = json.get( 'email' )

  if not all( [ username, email ] ):
    return {
      'success': False,
      'error': 'fields_missing',
      'message': 'Missing fields'
    }

  success, response = AuthService.request_password_reset( username, email )

  # In development mode, we might want to include the reset token in the response
  # In production, this should be removed
  if success and Config.EMAIL_ENABLED is False and 'reset_token' in response:
    # Only return the token if email sending is disabled (development mode)
    return { 'success': success, **response }
  elif 'reset_token' in response:
    # Remove token from response in production
    del response[ 'reset_token' ]

  return { 'success': success, **response }


@router.post( "/verify_email" )
async def verify_email( request: Request ) -> Dict[ str, Any ]:
  json = await request.json( )
  user_id = json.get( 'user_id' )
  token = json.get( 'token' )

  if not all( [ user_id, token ] ):
    return {
      'success': False,
      'error': 'fields_missing',
      'message': 'Missing user_id or token'
    }

  success, response = AuthService.verify_email( user_id, token )
  return { 'success': success, **response }


@router.post( "/update_password" )
async def update_password( request: Request ) -> Dict[ str, Any ]:
  json = await request.json( )
  username = json.get( 'username' )
  old_password = json.get( 'old_password' )
  new_password = json.get( 'new_password' )

  if not all( [ username, old_password, new_password ] ):
    return {
      'success': False,
      'error': 'fields_missing',
      'message': 'Missing or empty fields'
    }

  success, response = AuthService.update_password( username, old_password, new_password )
  return { 'success': success, **response }

async def verify_token( request: Request ):
  auth = request.headers.get( 'Authorization' )
  if not auth or not auth.startswith( 'Bearer ' ):
    raise HTTPException( status_code=401, detail='Invalid token' )

  token = auth.split( ' ' )[ 1 ]
  success, payload = AuthService.verify_jwt_token( token )

  if not success:
    raise HTTPException( status_code=401, detail=payload[ 'message' ] )

  return payload


@router.get( "/protected" )
async def protected_route( payload: Dict = Depends( verify_token ) ) -> Dict[ str, Any ]:
  return { 'user_id': payload[ 'user_id' ] }