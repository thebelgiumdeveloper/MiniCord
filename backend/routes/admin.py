from fastapi import APIRouter, Request, Response
import os

from ..config import Config
from ..database import init_db

router = APIRouter( tags=[ "admin" ] )


@router.get( '/create_db' )
async def create_db( request: Request ) -> dict:
  if Config.ADMIN_SECRET is None:
    return Response( status_code=404 )

  if (request.headers.get( 'Authorization' ) == Config.ADMIN_SECRET and
      request.headers.get( 'User-Agent' ) == Config.USER_AGENT):
    init_db( )
    return { 'success': True, 'message': 'Created Database' }
  else:
    return Response( status_code=404 )