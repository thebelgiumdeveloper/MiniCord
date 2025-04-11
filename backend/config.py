import os
from dotenv import load_dotenv
load_dotenv( )

class Config:
  DATABASE_URL = "minicord.db"
  JWT_SECRET = os.getenv( "JWT_SECRET" )
  JWT_EXPIRATION_MINUTES = 15
  EMAIL_VERIFICATION_HOURS = 24
  PASSWORD_RESET_HOURS = 1
  ADMIN_SECRET = os.getenv( "ADMIN_SECRET" )
  USER_AGENT = os.getenv( "USER_AGENT" )

  SMTP_SERVER = os.getenv( "SMTP_SERVER", "smtp.gmail.com" )
  SMTP_PORT = int( os.getenv( "SMTP_PORT", 587 ) )
  EMAIL_USERNAME = os.getenv( "EMAIL_USERNAME" )
  EMAIL_PASSWORD = os.getenv( "EMAIL_PASSWORD" )
  EMAIL_FROM = os.getenv( "EMAIL_FROM", EMAIL_USERNAME )
  EMAIL_ENABLED = os.getenv( "EMAIL_ENABLED", "True" ).lower( ) in ("true", "1", "yes")

  BASE_URL = os.getenv( "BASE_URL", "http://localhost:8000" )

  @classmethod
  def validate( cls ):
    if not cls.JWT_SECRET:
      raise ValueError( "JWT_SECRET not set in .env" )
    if cls.EMAIL_ENABLED:
      if not cls.EMAIL_USERNAME or not cls.EMAIL_PASSWORD:
        cls.EMAIL_ENABLED = False
    return True