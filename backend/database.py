import sqlite3
import os
from contextlib import contextmanager
from typing import Generator
from .config import Config

@contextmanager
def get_db_connection( ) -> Generator[ sqlite3.Connection, None, None ]:
  connection = sqlite3.connect( Config.DATABASE_URL )
  try:
    yield connection
  finally:
    connection.close( )


def init_db( ) -> None:
  with get_db_connection( ) as connection:
    cursor = connection.cursor( )

    cursor.execute( '''CREATE TABLE IF NOT EXISTS Users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email_hash TEXT NOT NULL,
            age BLOB,
            salt BLOB NOT NULL
        )''' )

    cursor.execute( '''CREATE TABLE IF NOT EXISTS Preferences (
            user_id TEXT PRIMARY KEY,
            theme TEXT DEFAULT 'dark',
            notifications INTEGER DEFAULT 1,
            language TEXT DEFAULT 'en',
            custom_css TEXT,
            FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
        )''' )

    cursor.execute( '''CREATE TABLE IF NOT EXISTS EmailVerifications (
            user_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
        )''' )

    connection.commit( )