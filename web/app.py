import os

from flask import Flask

from utils import get_secret
from models import db, User
from crypto_utils import hash_password, verify_password, generate_key_pair


app = Flask(__name__)
app.config['SECRET_KEY'] = get_secret('flask_key_file')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///app.db')


@app.route('/')
def hello():
    return "<h1>Hello World!!!</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)