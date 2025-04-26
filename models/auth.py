# models/auth.py
from starlette.authentication import AuthenticationBackend, AuthCredentials, UnauthenticatedUser
from itsdangerous import URLSafeSerializer, BadSignature

class BasicUser:
    def __init__(self, id: int, email: str, role: str):
        self.id = id
        self.email = email
        self.role = role

    def is_admin(self):
        return self.role == "admin"

# Replace with a strong key and store it safely
serializer = URLSafeSerializer("super-secret-key", salt="auth-cookie")

class BasicAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        token = conn.cookies.get("auth_token")
        if not token:
            return

        try:
            user_data = serializer.loads(token)
            user = BasicUser(
                id=user_data["id"],
                email=user_data["email"],
                role=user_data["role"]
            )
            return AuthCredentials(["authenticated"]), user
        except BadSignature:
            return
