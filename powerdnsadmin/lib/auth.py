from flask import request, Response
from functools import wraps
from powerdnsadmin.models.user import User
from werkzeug.security import check_password_hash

def dyndns_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return Response('Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

        user = User.query.filter_by(username=auth.username).first()
        if not user or not check_password_hash(user.password, auth.password):
            return Response('Invalid credentials', 403, {'WWW-Authenticate': 'Basic realm="Login Required"'})

        return f(*args, **kwargs)
    return decorated
