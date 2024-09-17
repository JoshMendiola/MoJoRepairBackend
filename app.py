import os

from flask import Flask, send_from_directory

app = Flask(__name__)

mojorepair_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'MoJoRepair'))


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/home')
def home():
    return send_from_directory(mojorepair_dir, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(mojorepair_dir, filename)


if __name__ == '__main__':
    app.run()
