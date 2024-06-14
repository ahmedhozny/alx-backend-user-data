#!/usr/bin/env python3
"""
Authentication service module
"""
from typing import Union
from uuid import uuid4

import bcrypt
from sqlalchemy.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initializes the Auth class.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Adds a new user to the database.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Validates the login credentials.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                password.encode('utf-8'), user.password.encode('utf-8')
            )
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Creates a new session with the database.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id

        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets a user based on a given session id."""
        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session.
        """
        try:
            return self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token.
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError("User {} does not exist".format(email))

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the password.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            self._db.update_user(
                user.id, password=_hash_password(password), reset_token=None
            )
        except NoResultFound:
            raise ValueError("User {} does not exist".format(reset_token))
