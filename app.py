import os
import threading
import time
import random
import re
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from google import genai
from google.api_core import exceptions as google_exceptions

# --- Configuration ---
DATABASE_URI = 'sqlite:///keys.db'
# Background scheduler interval remains at 1 hour.
SCHEDULER_INTERVAL = 3600
RETRY_COUNT = 3
RETRY_DELAY = 5  # seconds

# --- Application Setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

# --- Cryptography Setup ---
KEY_PATH = os.path.join(app.instance_path, 'encryption.key')

def load_or_generate_key():
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_PATH, 'wb') as f:
            f.write(key)
        print(f"IMPORTANT: New encryption key generated at {KEY_PATH}. Keep this file safe and private.")
        return key

encryption_key = load_or_generate_key()
cipher_suite = Fernet(encryption_key)

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode('utf-8')

def summarize_error_message(message: str) -> str:
    """
    Extracts key information (like status code and message) from a detailed error string.
    """
    if not message or not isinstance(message, str):
        return "No error message available."

    # Attempt to find a status code like 403, 429, etc.
    code_match = re.search(r"(\d{3})", message)
    code = code_match.group(1) if code_match else "N/A"

    # Attempt to find the 'message' field in the JSON-like string
    message_match = re.search(r"'message':\s*\"(.*?)\"", message)
    msg_text = message_match.group(1) if message_match else "Details not found."
    
    # If it's a simple client error, that might be the whole message
    if "Client Error:" in message and not message_match:
        return message

    return f"Code: {code}, Message: {msg_text}"

# --- Database Model ---
class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key_encrypted = db.Column(db.LargeBinary, nullable=False)
    label = db.Column(db.String(100))
    status = db.Column(db.String(20), default='Untested')
    availability_rate = db.Column(db.Float, default=100.0)
    purchase_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    warranty_period = db.Column(db.Integer, nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
    total_tests = db.Column(db.Integer, default=0)
    successful_tests = db.Column(db.Integer, default=0)
    last_tested_time = db.Column(db.DateTime)
    notes = db.Column(db.String(255))
    last_error_message = db.Column(db.String(500), nullable=True)

    @property
    def summarized_error_message(self):
        return summarize_error_message(self.last_error_message)

    @property
    def last_tested_beijing_time(self):
        if not self.last_tested_time:
            return 'N/A'
        
        # 1. Get the naive datetime from DB and make it timezone-aware (localize to UTC)
        utc_time = self.last_tested_time.replace(tzinfo=timezone.utc)
        
        # 2. Create a timezone object for Beijing Time (UTC+8)
        beijing_tz = timezone(timedelta(hours=8))
        
        # 3. Convert the UTC time to Beijing Time
        beijing_time = utc_time.astimezone(beijing_tz)
        
        # 4. Format it as requested
        return beijing_time.strftime('%Y-%m-%d %H:%M')

    @property
    def api_key(self):
        return decrypt_data(self.api_key_encrypted)


    @api_key.setter
    def api_key(self, value):
        self.api_key_encrypted = encrypt_data(value)

    @property
    def is_expired(self):
        expiry_time_from_db = self.expiry_time
        if expiry_time_from_db.tzinfo is None:
            # If the datetime from DB is naive, assume it's UTC and make it aware.
            expiry_time_from_db = expiry_time_from_db.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expiry_time_from_db

# --- Global variable for Round-Robin ---
round_robin_index = 0

# --- Gemini Key Test Function (Thread-Safe & Reliable) ---
def check_gemini_key(api_key: str) -> (bool, str):
    """
    根据用户要求，严格检查Gemini API密钥的有效性。
    - 使用 gemini-2.5-pro 模型。
    - 捕获并返回详细的错误信息。
    - 返回: (is_valid: bool, message: str)
    """
    try:
        # 严格按照用户示例代码
        client = genai.Client(api_key=api_key)
        client.models.generate_content(model="gemini-2.5-pro", contents="hello")
        return True, None
    except google_exceptions.PermissionDenied as e:
        # 专用于处理无效密钥的错误
        return False, f"Permission Denied: {e}"
    except google_exceptions.ClientError as e:
        # 专用于处理客户端错误，如资源耗尽（429）
        return False, f"Client Error: {e}"
    except Exception as e:
        # 捕获其他所有潜在错误（如网络问题）
        print(f"[Thread-Safe Check Error] Key ...{api_key[-4:]}: {e}")
        return False, f"An unexpected error occurred: {e}"

def _test_single_key_in_background(app_context, key_id):
    """Function to be run in a thread to test a key without blocking."""
    with app_context:
        print(f"BACKGROUND_TEST: Starting for key ID {key_id}.")
        key_obj = db.session.get(APIKey, key_id)
        if not key_obj:
            print(f"BACKGROUND_TEST: Key ID {key_id} not found.")
            return
            
        is_valid, error_message = False, "Initial error"
        for i in range(RETRY_COUNT):
            is_valid, error_message = check_gemini_key(key_obj.api_key)
            if is_valid:
                break
            if i < RETRY_COUNT - 1:
                time.sleep(RETRY_DELAY)

        key_obj.total_tests += 1
        key_obj.last_error_message = error_message # 存储错误信息
        if is_valid:
            key_obj.status = 'Available'
            key_obj.successful_tests += 1
        else:
            key_obj.status = 'Unavailable'
        
        if key_obj.total_tests > 0:
            key_obj.availability_rate = (key_obj.successful_tests / key_obj.total_tests) * 100
        
        key_obj.last_tested_time = datetime.now(timezone.utc)
        db.session.commit()
        print(f"BACKGROUND_TEST: Finished for key ID {key_id}. Status: {key_obj.status}")

# --- Background Task ---
def test_all_keys_job():
    with app.app_context():
        print("SCHEDULER: Running scheduled key tests...")
        keys = APIKey.query.all()
        for key in keys:
            thread = threading.Thread(target=_test_single_key_in_background, args=(app.app_context(), key.id))
            thread.start()
        print("SCHEDULER: All test threads started.")

# --- Routes ---
@app.route('/')
def index():
    status_filter = request.args.get('status_filter', 'all')
    warranty_filter = request.args.get('warranty_filter', 'all')

    query = APIKey.query

    # 应用可用状态筛选
    if status_filter == 'available':
        query = query.filter(APIKey.status == 'Available')
    elif status_filter == 'unavailable':
        query = query.filter(APIKey.status == 'Unavailable')
    elif status_filter == 'untested':
        query = query.filter(APIKey.status == 'Untested')

    # 应用质保状态筛选
    # 我们不能直接在数据库中按 is_expired 属性筛选，
    # 所以需要在查询中复现这个逻辑。
    now_utc = datetime.now(timezone.utc)
    if warranty_filter == 'active':
        query = query.filter(APIKey.expiry_time > now_utc)
    elif warranty_filter == 'expired':
        query = query.filter(APIKey.expiry_time <= now_utc)

    # 应用排序
    keys = query.order_by(APIKey.availability_rate.desc()).all()
    
    return render_template('index.html', 
                           keys=keys, 
                           status_filter=status_filter, 
                           warranty_filter=warranty_filter)

@app.route('/add', methods=['POST'])
def add_key():
    api_keys = request.form['api_keys'].strip().splitlines()
    label = request.form['label']
    warranty_period = int(request.form['warranty_period'])
    
    newly_added_ids = []
    for key_str in api_keys:
        if key_str:
            purchase_dt = datetime.now(timezone.utc)
            expiry_dt = purchase_dt + timedelta(days=warranty_period)
            new_key = APIKey(
                label=label,
                warranty_period=warranty_period,
                purchase_time=purchase_dt,
                expiry_time=expiry_dt
            )
            new_key.api_key = key_str.strip()
            db.session.add(new_key)
            db.session.flush()
            newly_added_ids.append(new_key.id)

    db.session.commit()

    for key_id in newly_added_ids:
        thread = threading.Thread(target=_test_single_key_in_background, args=(app.app_context(), key_id))
        thread.start()

    flash(f'{len(newly_added_ids)} key(s) added. Testing will complete shortly.')
    return redirect(url_for('index'))

@app.route('/delete/<int:key_id>', methods=['POST'])
def delete_key(key_id):
    key = db.session.get(APIKey, key_id)
    if key:
        db.session.delete(key)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Key deleted.'})
    return jsonify({'success': False, 'message': 'Key not found.'}), 404

@app.route('/test/<int:key_id>', methods=['POST'])
def test_key(key_id):
    thread = threading.Thread(target=_test_single_key_in_background, args=(app.app_context(), key_id))
    thread.start()
    return jsonify({
        'success': True,
        'message': 'Test initiated. The status will update shortly.'
    })

@app.route('/copy', methods=['GET'])
def quick_copy():
    """
    快速复制功能 - 方案二：实时验证轮询 (最可靠)
    在提供密钥前，会先对密钥进行一次实时的有效性验证。
    """
    global round_robin_index
    
    # 1. 获取所有理论上可用的密钥
    candidate_keys = APIKey.query.filter_by(status='Available').order_by(APIKey.availability_rate.desc()).all()
    
    if not candidate_keys:
        return jsonify({'error': '数据库中没有标记为“可用”的密钥。'}), 404

    # 确保轮询索引不会越界
    if round_robin_index >= len(candidate_keys):
        round_robin_index = 0
        
    num_candidates = len(candidate_keys)
    # 2. 从当前轮询位置开始，遍历所有候选密钥，直到找到一个真正可用的
    for i in range(num_candidates):
        current_index = (round_robin_index + i) % num_candidates
        key_to_test = candidate_keys[current_index]
        
        # 3. 对密钥进行实时测试
        print(f"QUICK_COPY: Real-time checking key ...{key_to_test.api_key[-4:]}")
        is_valid, error_message = check_gemini_key(key_to_test.api_key)
        
        # 4. 如果测试成功
        if is_valid:
            print(f"QUICK_COPY: Key ...{key_to_test.api_key[-4:]} is valid. Returning.")
            # 清除旧的错误信息
            if key_to_test.last_error_message:
                key_to_test.last_error_message = None
                db.session.commit()
            # 更新下一次开始的索引
            round_robin_index = (current_index + 1) % num_candidates
            # 返回有效的密钥
            return jsonify({'api_key': key_to_test.api_key})
            
        # 5. 如果测试失败
        else:
            print(f"QUICK_COPY: Key ...{key_to_test.api_key[-4:]} failed. Marking as unavailable.")
            # 更新数据库状态
            key_to_test.status = 'Unavailable'
            key_to_test.last_error_message = error_message # 记录新的错误信息
            key_to_test.total_tests += 1 # 本次测试也计入总数
            if key_to_test.total_tests > 0:
                key_to_test.availability_rate = (key_to_test.successful_tests / key_to_test.total_tests) * 100
            key_to_test.last_tested_time = datetime.now(timezone.utc)
            db.session.commit()

    # 6. 如果循环走完都没有找到可用的密钥
    print("QUICK_COPY: All candidate keys failed the real-time check.")
    return jsonify({'error': '所有“可用”密钥在实时检查中均验证失败。'}), 404

@app.route('/get_updates')
def get_updates():
    """An endpoint to fetch the latest status of all keys."""
    keys = APIKey.query.all()
    keys_data = []
    for key in keys:
        keys_data.append({
            'id': key.id,
            'status': key.status,
            'availability_rate': f"{key.availability_rate:.2f}%",
            'last_tested': key.last_tested_beijing_time,
            'last_error_message': key.last_error_message,
            'summarized_error_message': key.summarized_error_message
        })
    return jsonify(keys_data)

@app.route('/test_all', methods=['POST'])
def test_all():
    """Triggers a background test for all keys."""
    with app.app_context():
        keys = APIKey.query.all()
        for key in keys:
            thread = threading.Thread(target=_test_single_key_in_background, args=(app.app_context(), key.id))
            thread.start()
    return jsonify({'success': True, 'message': f'Initiated tests for all {len(keys)} keys.'})

# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(test_all_keys_job, 'interval', seconds=SCHEDULER_INTERVAL)
    scheduler.start()
    
    print(f"Starting Flask app on http://0.0.0.0:3000 with a test interval of {SCHEDULER_INTERVAL} seconds.")
    from waitress import serve
    serve(app, host='0.0.0.0', port=3000)
