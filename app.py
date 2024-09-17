import os

from flask import Flask, send_from_directory

app = Flask(__name__)

mojorepair_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'MoJoRepair'))


@app.route('/')
def home():
    return send_from_directory(mojorepair_dir, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    if filename.startswith('html/'):
        return send_from_directory(mojorepair_dir, filename)
    elif filename in ['about', 'services', 'login', 'register']:
        return send_from_directory(os.path.join(mojorepair_dir, 'html'), f'{filename}.html')
    else:
        file_path = os.path.join(mojorepair_dir, filename)
        if os.path.isfile(file_path):
            return send_from_directory(mojorepair_dir, filename)
        else:
            os.abort(404)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
