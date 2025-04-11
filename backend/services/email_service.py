import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Optional

from ..config import Config

logger = logging.getLogger( __name__ )


class EmailService:
  @classmethod
  def _create_message( cls, to_email: str, subject: str, html_content: str,
                       text_content: Optional[ str ] = None ) -> MIMEMultipart:
    message = MIMEMultipart( "alternative" )
    message[ "Subject" ] = subject
    message[ "From" ] = Config.EMAIL_FROM
    print('email : ', to_email)
    message[ "To" ] = to_email

    if text_content:
      plain_part = MIMEText( text_content, "plain" )
      message.attach( plain_part )
    else:
      plain_text = html_content.replace( "<p>", "" ).replace( "</p>", "\n\n" )
      plain_text = plain_text.replace( "<br>", "\n" ).replace( "<br/>", "\n" )
      plain_part = MIMEText( plain_text, "plain" )
      message.attach( plain_part )

    html_part = MIMEText( html_content, "html" )
    message.attach( html_part )

    return message

  @classmethod
  def _send_email( cls, to_email: str, subject: str, message: MIMEMultipart ) -> bool:
    if not Config.EMAIL_ENABLED:
      logger.warning( f"Email sending is disabled. Would have sent to {to_email}: {subject}" )
      return False

    try:
      with smtplib.SMTP( Config.SMTP_SERVER, Config.SMTP_PORT ) as server:
        server.ehlo( )
        server.starttls( )
        server.ehlo( )
        server.login( Config.EMAIL_USERNAME, Config.EMAIL_PASSWORD )
        server.sendmail( Config.EMAIL_FROM, to_email, message.as_string( ) )
      logger.info( f"Email sent successfully to {to_email}" )
      return True
    except Exception as e:
      logger.error( f"Failed to send email to {to_email}: {str( e )}" )
      return False

  @classmethod
  def send_verification_email( cls, email: str, user_id: str, token: str ) -> bool:
    print(f'send_verification_email : {email}')
    subject = "Verify your Minicord account"
    verification_url = f"{Config.BASE_URL}/verify_email?user_id={user_id}&token={token}"

    html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .button {{ background-color: #7289DA; color: white; padding: 10px 20px; 
                           text-decoration: none; border-radius: 4px; display: inline-block; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Welcome to Minicord!</h2>
                <p>Thank you for registering. To verify your email address and activate your account, please click the button below:</p>
                <p><a href="{verification_url}" class="button">Verify Email Address</a></p>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p>{verification_url}</p>
                <p>This verification link will expire in {Config.EMAIL_VERIFICATION_HOURS} hours.</p>
                <div class="footer">
                    <p>If you did not create an account with Minicord, please ignore this email.</p>
                </div>
            </div>
        </body>
        </html>
        """

    text_content = f"""
        Welcome to Minicord!

        Thank you for registering. To verify your email address and activate your account, please visit this link:

        {verification_url}

        This verification link will expire in {Config.EMAIL_VERIFICATION_HOURS} hours.

        If you did not create an account with Minicord, please ignore this email.
        """

    message = cls._create_message( email, subject, html_content, text_content )
    return cls._send_email( email, subject, message )

  @classmethod
  def send_password_reset_email( cls, email: str, user_id: str, token: str ) -> bool:
    subject = "Reset your Minicord password"
    reset_url = f"{Config.BASE_URL}/update_password?user_id={user_id}&token={token}"

    html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .button {{ background-color: #7289DA; color: white; padding: 10px 20px; 
                           text-decoration: none; border-radius: 4px; display: inline-block; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #777; }}
                .warning {{ color: #E74C3C; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Password Reset Request</h2>
                <p>We received a request to reset your password for your Minicord account. To set a new password, click the button below:</p>
                <p><a href="{reset_url}" class="button">Reset Password</a></p>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p>{reset_url}</p>
                <p class="warning">This password reset link will expire in {Config.PASSWORD_RESET_HOURS} hours.</p>
                <div class="footer">
                    <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                </div>
            </div>
        </body>
        </html>
        """

    text_content = f"""
        Password Reset Request

        We received a request to reset your password for your Minicord account. To set a new password, please visit this link:

        {reset_url}

        This password reset link will expire in {Config.PASSWORD_RESET_HOURS} hours.

        If you did not request a password reset, please ignore this email or contact support if you have concerns.
        """

    message = cls._create_message( email, subject, html_content, text_content )
    return cls._send_email( email, subject, message )