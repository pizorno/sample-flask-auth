from flask import Flask, request, jsonify
from sqlalchemy.sql.functions import current_user
from werkzeug.security import gen_salt

from models.user import User
from database import db
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = \
    "mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud"

login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if data["username"] and data["password"]:
        user = User.query.filter_by(username=data.get("username")).first()
        if user and bcrypt.checkpw(str.encode(data["password"]), str.encode(
                user.password)):
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"})
    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso."})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.json
    user = User.query.filter_by(username=data.get("username")).first()
    if user and data["username"] == user.username:
        return jsonify({"message": "Ação não permitida"}),403
    if data["username"] and data["password"]:
        user = User(username=data.get("username"),
                    password=bcrypt.hashpw(str.encode(data["password"]),
                                           bcrypt.gensalt(14)))
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"})
    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({"username": user.username})
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.json
    user = User.query.get(user_id)
    if current_user.role == "user" and current_user.id != user_id:
        return jsonify({"message": "Operação não permitida"}), 403
    if user and data["password"]:
        user.password = bcrypt.hashpw(str.encode(data["password"]),
                                      bcrypt.gensalt(14))
        db.session.commit()
        return jsonify({"message": f"Usuário {user_id} atualizado com sucesso"})
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if current_user.role == "user" and current_user.id != user_id:
        return jsonify({"message": "Operação não permitida"}), 403
    if user_id == current_user.id:
        return jsonify({"message": "Operação não permitida"}), 403
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {user_id} removido com sucesso"})
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/hello-world', methods=['GET'])
def hello_world():
    return "Hello World!"

if __name__ == "__main__":
    app.run(debug=True)