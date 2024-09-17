import os
from flask import Flask, send_from_directory, abort
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

mojorepair_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'MoJoRepair'))


@app.route('/')
def home():
    app.logger.info(f"Serving home page from {mojorepair_dir}/index.html")
    return send_from_directory(mojorepair_dir, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    app.logger.info(f"Request for: /{filename}")

    if filename in ['about', 'services', 'login', 'register']:
        file_path = os.path.join(mojorepair_dir, 'html', f'{filename}.html')
        app.logger.info(f"Attempting to serve: {file_path}")
        if os.path.isfile(file_path):
            return send_from_directory(os.path.join(mojorepair_dir, 'html'), f'{filename}.html')
        else:
            app.logger.error(f"File not found: {file_path}")
            abort(404)
    else:
        file_path = os.path.join(mojorepair_dir, filename)
        app.logger.info(f"Attempting to serve: {file_path}")
        if os.path.isfile(file_path):
            return send_from_directory(mojorepair_dir, filename)
        else:
            app.logger.error(f"File not found: {file_path}")
            abort(404)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)