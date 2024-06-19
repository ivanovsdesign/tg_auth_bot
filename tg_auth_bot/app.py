# app.py
from flask import Flask, request, jsonify
import hashlib
import hmac
from dotenv import dotenv_values

app = Flask(__name__)

config = dotenv_values('.env')

TELEGRAM_TOKEN = config['TELEGRAM_BOT_TOKEN']

def check_signature(data):
    secret_key = hashlib.sha256(TELEGRAM_TOKEN.encode()).digest()
    data_check_string = "\n".join([f"{key}={value}" for key, value in sorted(data.items()) if key != 'hash'])
    hash_to_check = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hash_to_check == data['hash']

@app.route('/auth/telegram', methods=['GET'])
def telegram_auth():
    data = request.args.to_dict()
    if check_signature(data):
        return jsonify(success=True, user=data), 200
    else:
        return jsonify(success=False, message='Invalid signature'), 401

if __name__ == '__main__':
    app.run(debug=True)