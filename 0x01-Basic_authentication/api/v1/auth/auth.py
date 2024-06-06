#!/usr/bin/env python3
"""
Authentication module
"""
from typing import List, TypeVar

from flask import request


class Auth:
    """
    Authentication class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if path requires authentication.
        """
        if path is None:
            return True
        if not excluded_paths:
            return True

        if not path.endswith('/'):
            path += '/'

        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieve the Authorization header from the request.
        """
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user from the request.
        """
        return None
