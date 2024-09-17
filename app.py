import os

from flask import Flask, send_from_directory

app = Flask(__name__)

mojorepair_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'MoJoRepair'))


@app.route('/')
def home():
    return send_from_directory(mojorepair_dir, 'index.html')


@app.route('/about')
def about():
    return send_from_directory(os.path.join(mojorepair_dir, 'html'), 'about.html')


@app.route('/services')
def services():
    return send_from_directory(os.path.join(mojorepair_dir, 'html'), 'services.html')


@app.route('/login')
def login():
    return send_from_directory(os.path.join(mojorepair_dir, 'html'), 'login.html')


@app.route('/register')
def register():
    return send_from_directory(os.path.join(mojorepair_dir, 'html'), 'register.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
