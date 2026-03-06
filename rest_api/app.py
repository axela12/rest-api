from flask import Flask, request, jsonify, BadRequest
from mysql.connector import connect, Error
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required
)
from datetime import timedelta

app = Flask(__name__)

JWT_SECRET = "super_hemlig_nyckel"
JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = 30

app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ALGORITHM"] = JWT_ALGORITHM
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=JWT_EXP_MINUTES)

jwt = JWTManager(app)

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "forum_db"
}

def get_db_connection():
    try:
        return connect(**DB_CONFIG)
    except Error as e:
        print(f"Databasfel: {e}")
        return None

@app.route("/", methods=["GET"])
def index():
    
    return jsonify({
        "routes": {
            "POST /login": "Öppen, returnerar JWT",
            "POST /users": "Öppen, registrera användare",
            "GET /users": "Kräver inloggning (JWT)",
            "GET /users/<id>": "Kräver inloggning (JWT)",
            "PUT /users/<id>": "Kräver inloggning (JWT)"
        },
    })

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
    except BadRequest:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()

    if user and check_password_hash(user["password"], password):
        access_token = create_access_token(
            identity=str(user["id"]),
            additional_claims={"name": user["name"]}
        )
        return jsonify({"token": access_token}), 200

    return jsonify({"error": "Ogiltigt användarnamn eller lösenord"}), 401

@app.route("/users", methods=["POST"])
def post_user():
    try:
        data = request.get_json()
    except BadRequest:
        return jsonify({"error": "Invalid JSON"}), 400

    name = data.get("name")
    username = data.get("username")
    password = data.get("password")

    if not name or not username or not password:
        return jsonify({"error": "Alla fält måste fyllas i"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        return jsonify({"error": "Användarnamn finns redan"}), 409

    hashed_password = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (username, name, password) VALUES (%s, %s, %s)",
        (username, name, hashed_password)
    )
    connection.commit()
    cursor.close()
    connection.close()

    return jsonify({"message": "Användare skapad"}), 201

@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id, username, name FROM users")
    users = cursor.fetchall()

    cursor.close()
    connection.close()

    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, username, name FROM users WHERE id = %s",
        (user_id,)
    )
    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:
        return jsonify({"error": "Användaren hittades inte"}), 404

    return jsonify(user)

@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def put_user(id):
    try:
        data = request.get_json()
    except BadRequest:
        return jsonify({"error": "Invalid JSON"}), 400

    name = data.get("name")
    username = data.get("username")
    password = data.get("password")

    if not name or not username or not password:
        return jsonify({"error": "Alla fält måste fyllas i"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE id = %s", (id,))
    if not cursor.fetchone():
        return jsonify({"error": "User not found"}), 404

    hashed_password = generate_password_hash(password)
    cursor.execute(
        """
        UPDATE users
        SET username = %s, name = %s, password = %s
        WHERE id = %s
        """,
        (username, name, hashed_password, id)
    )
    connection.commit()

    cursor.close()
    connection.close()

    return jsonify({"message": "Användare uppdaterad"}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
