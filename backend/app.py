from flask import Flask, make_response, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import redis
import logging
import os
import bcrypt
import uuid
from flask_cors import CORS, cross_origin

# Set up the application
basedir = os.path.abspath(os.path.dirname(__file__))

logging.basicConfig(
    filename='app.log',level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

db = SQLAlchemy()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    basedir, "app.sqlite"
)
db.init_app(app)
redis_client = redis.StrictRedis(host="redis", port=6379, db=0)
CORS(
    app,
    allow_headers="*",
    expose_headers=[
        "tokens",
        "Set-Cookie",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
    ],
    supports_credentials=True,
)

# Define database models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    email = db.Column(db.String(100), unique=True)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"))
    role = db.relationship("Role", backref=db.backref("users"))


class Inbox(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    tags = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now())
    deadline = db.Column(db.DateTime, default=datetime.now() + timedelta(days=10))


# Utility functions for password and session management
def generate_hash(password: str) -> bytes:
    """Generate a bcrypt hash for the given password."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)


def verify_password(input_password: str, hashed_password: bytes) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(input_password.encode("utf-8"), hashed_password)


def generate_session_key() -> str:
    """Generate a unique session key using UUID."""
    return str(uuid.uuid4())


def add_to_session(session_key: str, data: dict):
    """Add data to the session in Redis."""
    redis_client.hmset(session_key, data)
    redis_client.expire(session_key, 3600)


def get_session_data(session_key: str):
    """Retrieve session data from Redis."""
    return redis_client.hgetall(session_key)


def is_authenticated(username: str) -> bool:
    """Check if a user is authenticated."""
    return True


# Database initialization and role setup
with app.app_context():
    db.create_all()

    # Create roles if not present
    if Role.query.filter_by(id=1).first() is None:
        role_admin = Role()
        role_admin.id = 1
        role_admin.name = "ADMIN"
        db.session.add(role_admin)

    if Role.query.filter_by(id=2).first() is None:
        role_user = Role()
        role_user.id = 2
        role_user.name = "USER"
        db.session.add(role_user)

    db.session.commit()
    logger.info("DB Created")


# Routes for testing, registration, login, and logout
@app.route("/test")
def test():
    """A simple test route."""
    return "App Running!"


@app.route("/register", methods=["POST"])
def register():
    """Register a new user."""
    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        hashed_password = generate_hash(password)
        if User.query.filter_by(username=username).first() is None:
            new_user = User()
            new_user.username = username
            new_user.name = name
            new_user.password = hashed_password
            new_user.role_id = 2
            new_user.email = email
            db.session.add(new_user)
            db.session.commit()
            return "USER CREATED!"
        else:
            return "USER EXISTS!"
    else:
        return "Invalid Request!!"


@app.route("/login", methods=["POST"])
def login():
    """Authenticate and log in a user."""
    if request.method == "POST":
        username = request.form.get("loginUsername")
        password = request.form.get("loginPassword")
        if username is None or password is None:
            return "Bad Query!"
        else:
            hashed_password = generate_hash(password)
        queried_user = User.query.filter_by(username=username).first()
        if queried_user is None:
            return "User Does Not Exist!"
        else:
            if verify_password(password, queried_user.password):
                session_data = {
                    "username": username,
                    "login_time": datetime.now().isoformat(),
                    "role": queried_user.role_id,
                }
                session_key = generate_session_key()
                add_to_session(session_key, session_data)
                response = make_response("Login Successful!")
                print("LOGS: Session Key:")
                print(session_key)
                response.set_cookie(
                    "session_key", value=session_key, max_age=3600, domain="localhost"
                )
                return response
            else:
                return "Wrong Password! Please Try Again."
    else:
        return "Login Page coming soon!"


@app.route("/logout", methods=["GET"])
def logout():
    """Log out a user and clear the session."""
    session_key = request.cookies.get("session_key")
    if session_key:
        redis_client.delete(session_key)
    response = make_response("Logged Out Successfully!")
    response.set_cookie("session_key", "", expires=0)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
