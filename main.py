from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt  # Import the Bcrypt module
import datetime

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/flask"
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["SECRET_KEY"] = "9869340732"
app.config["BCRYPT_LOG_ROUNDS"] = 12  # Set the Bcrypt log rounds (adjust as needed)
bcrypt = Bcrypt(app)  # Initialize Bcrypt
jwt = JWTManager(app)
db = PyMongo(app).db
cors = CORS(app)
app.config["CORS_HEADERS"] = "Content-Type"

@app.route("/signup", methods=["POST"])
def signup():
    content = request.get_json()

    required_fields = ["username", "password", "email", "address", "phone_number"]
    for field in required_fields:
        if field not in content:
            return jsonify({"error": f"'{field}' is required"}), 400

    # Check if the email already exists
    if db.users.find_one({"email": content["email"]}):
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(content["password"]).decode("utf-8")

    user_data = {
        "username": content["username"],
        "password": hashed_password,
        "email": content["email"],
        "address": content["address"],
        "phone_number": content["phone_number"],
    }

    db.users.insert_one(user_data)

    token = create_access_token(identity=content["username"])

    return jsonify({"message": "Signup successful", "token": token})


@app.route("/login", methods=["POST"])
def login():
    content = request.get_json()
    user = db.users.find_one({"username": content["username"]})

    if user and bcrypt.check_password_hash(user["password"], content["password"]):
        token = create_access_token(identity=content["username"])
        return jsonify({"message": "Login successful", "token": token})
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run(debug=True, port=5002)
