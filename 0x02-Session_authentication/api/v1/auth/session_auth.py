#!/usr/bin/env python3
"""
Session authentication module
"""
import uuid
from typing import TypeVar

from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """
    Session authentication class
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create session
        """
        if user_id is None:
            return None

        if not isinstance(user_id, str):
            return None

        sess_id = str(uuid.uuid4())
        SessionAuth.user_id_by_session_id[sess_id] = user_id
        return sess_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        retrieve user id from session id
        :param session_id:
        :return:
        """
        if session_id is None:
            return None

        if not isinstance(session_id, str):
            return None

        return SessionAuth.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        return current user object
        """
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        print(user_id)
        return User.get(user_id)

    def destroy_session(self, request=None) -> bool:
        """
        destroys user session
        """
        from api.v1.app import auth
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if request is None or session_id is None or user_id is None:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
