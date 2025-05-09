from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from markupsafe import Markup
import os
import time
import uuid
import shutil
import threading
import subprocess
import datetime
import re
import random
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.template_filter('safe_message')
def safe_message(message):
    if message and isinstance(message, str):
        return Markup(message)
    return message

BASE_INSTANCE_DIR = "/tmp/underworld_instances"
INSTANCE_TIMEOUT = 60 * 60
FLAG = "O24{th3_scr1b3_r3v34ls_h1dd3n_tr34sur3s}"

if not os.path.exists(BASE_INSTANCE_DIR):
    os.makedirs(BASE_INSTANCE_DIR)

active_instances = {}
instance_lock = threading.Lock()

STATIC_IMAGES = [
    "papyrus-texture.jpg",
    "anubis.jpg",
    "thoth.jpg",
    "scales-of-justice.png"
]

def setup_virtual_fs(instance_id):
    instance_dir = os.path.join(BASE_INSTANCE_DIR, instance_id)

    os.makedirs(instance_dir, exist_ok=True)
    os.makedirs(os.path.join(instance_dir, "var", "log", "ritual"), exist_ok=True)
    os.makedirs(os.path.join(instance_dir, "home", "high_priest"), exist_ok=True)
    os.makedirs(os.path.join(instance_dir, "etc", "temple"), exist_ok=True)
    os.makedirs(os.path.join(instance_dir, "var", "www", "html", "static", "images"), exist_ok=True)

    cmd_log_path = os.path.join(instance_dir, "var", "log", "cmd.log")
    with open(cmd_log_path, "w") as f:
        f.write("")

    print(f"\n*** Setting up virtual filesystem for instance {instance_id} ***")
    src_images_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "images")
    dst_images_dir = os.path.join(instance_dir, "var", "www", "html", "static", "images")

    print(f"Source images directory: {src_images_dir}")
    print(f"Destination images directory: {dst_images_dir}")
    print(f"Instance directory exists: {os.path.exists(instance_dir)}")
    print(f"Destination directory exists: {os.path.exists(dst_images_dir)}")

    os.makedirs(dst_images_dir, exist_ok=True)

    print("Files in source directory:")
    if os.path.exists(src_images_dir):
        for f in os.listdir(src_images_dir):
            print(f"  - {f}")
    else:
        print("  Source directory does not exist!")

    for image_file in STATIC_IMAGES:
        src_path = os.path.join(src_images_dir, image_file)
        dst_path = os.path.join(dst_images_dir, image_file)
        if os.path.exists(src_path):
            print(f"Copying {src_path} to {dst_path}")
            shutil.copy(src_path, dst_path)
        else:
            print(f"Source image not found: {src_path}")
            with open(dst_path, "w") as f:
                f.write(f"Placeholder for {image_file}")

    print("Files in destination directory after copy:")
    for f in os.listdir(dst_images_dir):
        print(f"  - {f}")

    with open(os.path.join(instance_dir, "home", "high_priest", "sacred_scroll.txt"), "w") as f:
        f.write(FLAG)

    with open(os.path.join(instance_dir, "etc", "temple", "config.ini"), "w") as f:
        f.write("""[System]
Logs=/var/log/ritual

[Security]
SacredTexts=/home/high_priest/sacred_scroll.txt
DailyBackup=true
""")

    for i in range(1, 4):
        with open(os.path.join(instance_dir, "var", "log", "ritual", f"ritual_{i}.log"), "w") as f:
            f.write(f"Ritual {i} performed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Offering: {['wheat', 'bread', 'gold', 'incense'][i % 4]}\n")
            f.write(f"Presiding Priest: {['Amenhotep', 'Ramose', 'Ptahmose'][i % 3]}\n")

    with open(os.path.join(instance_dir, "var", "log", "auth.log"), "w") as f:
        f.write(f"""Apr 22 09:15:23 oracle-server sudo: junior_priest : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/junior_priest ; USER=high_priest ; COMMAND=/usr/bin/cat /home/high_priest/sacred_scroll.txt
Apr 22 09:16:45 oracle-server sudo: www-data : TTY=unknown ; PWD=/var/www/html ; USER=high_priest ; COMMAND=/usr/bin/cat /var/log/ritual/daily_offerings.log
""")

    return instance_dir

def cleanup_instance(instance_id):
    with instance_lock:
        if instance_id in active_instances:
            instance_dir = os.path.join(BASE_INSTANCE_DIR, instance_id)
            try:
                if os.path.exists(instance_dir):
                    shutil.rmtree(instance_dir)
                del active_instances[instance_id]
            except Exception as e:
                print(f"Error cleaning up instance {instance_id}: {str(e)}")

def check_expired_instances():
    current_time = time.time()
    expired = []

    with instance_lock:
        for instance_id, expiration in list(active_instances.items()):
            if current_time > expiration:
                expired.append(instance_id)

    for instance_id in expired:
        cleanup_instance(instance_id)

def simulate_command_execution(command, instance_dir):
    print(f"Processing command: {command}")

    cmd_patterns = [
        r';(.*)',
        r'&&(.*)',
        r'\|\|(.*)',
        r'\|(.*)',
        r'`(.*)`',
        r'\$\((.*)\)',
        r'&(.*)'
    ]

    injected_cmd = None
    for pattern in cmd_patterns:
        match = re.search(pattern, command)
        if match:
            injected_cmd = match.group(1).strip()
            break

    if not injected_cmd:
        print(f"No command injection pattern found in: {command}")
        return None

    print(f"Detected injected command: {injected_cmd}")

    result = ""

    if injected_cmd == "whoami":
        result = "www-data"
    elif injected_cmd == "id":
        result = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    elif injected_cmd == "pwd":
        result = "/var/www/html"

    elif injected_cmd == "sudo -l":
        result = """User www-data may run the following commands on oracle-server:
    (high_priest) NOPASSWD: /usr/bin/cat /var/log/ritual/*
"""

    elif injected_cmd == "ls":
        result = "ritual_1.log  ritual_2.log  ritual_3.log"

    elif injected_cmd == "cat ritual_1.log":
        result = """Ritual 1 performed at 2025-04-22 08:15:23
Offering: wheat
Presiding Priest: Amenhotep
Note: High Priest keeps sacred_scroll.txt in their home directory."""
    elif injected_cmd == "cat ritual_2.log":
        result = """Ritual 2 performed at 2025-04-22 10:30:45
Offering: bread
Presiding Priest: Ramose
Warning: Remember that the power of sudo must be wielded with precision. Always specify the full path to commands."""
    elif injected_cmd == "cat ritual_3.log":
        result = """Ritual 3 performed at 2025-04-22 14:22:10
Offering: gold
Presiding Priest: Ptahmose
Note: Guard the sacred /path/, for each /traversal/ may awaken curses best left untouched."""

    elif "sudo -u high_priest /usr/bin/cat /var/log/ritual/" in injected_cmd and "home/high_priest/sacred_scroll.txt" in injected_cmd:
        if "../../../home/high_priest/sacred_scroll.txt" in injected_cmd or "../../home/high_priest/sacred_scroll.txt" in injected_cmd:
            result = FLAG
        else:
            result = "File not found or could not be read by high_priest."

    elif "sudo -u high_priest" in injected_cmd:
        if "/usr/bin/cat /var/log/ritual/ritual_1.log" in injected_cmd:
            result = """Ritual 1 performed at 2025-04-22 08:15:23
Offering: wheat
Presiding Priest: Amenhotep
Note: High Priest keeps sacred_scroll.txt in their home directory."""
        elif "/usr/bin/cat /var/log/ritual/ritual_2.log" in injected_cmd:
            result = """Ritual 2 performed at 2025-04-22 10:30:45
Offering: bread
Presiding Priest: Ramose
Warning: Remember that the power of sudo must be wielded with precision. Always specify the full path to commands."""
        elif "/usr/bin/cat /var/log/ritual/ritual_3.log" in injected_cmd:
            result = """Ritual 3 performed at 2025-04-22 14:22:10
Offering: gold
Presiding Priest: Ptahmose
Note: Guard the sacred /path/, for each /traversal/ may awaken curses best left untouched."""
        else:
            result = "sudo: sorry, you may only run /usr/bin/cat /var/log/ritual/* as high_priest on oracle-server"

    else:
        result = f"{injected_cmd}: command not found"

    print(f"Command result: {result[:50]}...")
    return result

def run_user_query(query, instance_dir):
    if not query or not query.strip():
        return "Please enter a name to query the Book of the Dead.", None

    command = f"query_book_of_dead {query}"
    print(f"Original command: {command}")

    try:
        cmd_log_path = os.path.join(instance_dir, "var", "log", "cmd.log")
        os.makedirs(os.path.dirname(cmd_log_path), exist_ok=True)
        with open(cmd_log_path, "a+") as f:
            f.write(f"{datetime.datetime.now()}: {command}\n")
    except Exception as e:
        print(f"Warning: Could not write to command log: {str(e)}")

    cmd_output = simulate_command_execution(command, instance_dir)

    fates = [
        f"The soul of {query} will find peace in the Field of Reeds.",
        f"The scales of Ma'at have weighed the heart of {query} and found it worthy.",
        f"The journey of {query} through Duat will be difficult but successful.",
        f"The heart of {query} is lighter than the feather of truth.",
        f"Anubis has judged {query} and found them deserving of the afterlife.",
        f"{query} must face the trials of the underworld with courage.",
        f"The Book of the Dead records that {query} will live for eternity.",
        f"Thoth has inscribed the name of {query} in the sacred scrolls."
    ]

    fate = random.choice(fates)

    return fate, cmd_output

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.args.get('reset') == 'true':
        if 'instance_id' in session:
            instance_id = session.pop('instance_id')
            cleanup_instance(instance_id)

    check_expired_instances()

    instance_id = session.get('instance_id')
    remaining_time = 0
    result = None
    cmd_output = None

    if instance_id:
        with instance_lock:
            if instance_id in active_instances:
                remaining_time = int(active_instances[instance_id] - time.time())
                if remaining_time <= 0:
                    cleanup_instance(instance_id)
                    instance_id = None

    if not instance_id:
        instance_id = str(uuid.uuid4())
        instance_dir = setup_virtual_fs(instance_id)

        with instance_lock:
            active_instances[instance_id] = time.time() + INSTANCE_TIMEOUT

        session['instance_id'] = instance_id
        remaining_time = INSTANCE_TIMEOUT

    if request.method == 'POST':
        name = request.form.get('name', '')
        instance_dir = os.path.join(BASE_INSTANCE_DIR, instance_id)
        result, cmd_output = run_user_query(name, instance_dir)

        if cmd_output:
            response = app.make_response(render_template('index.html',
                                         remaining_time=remaining_time,
                                         result=result))

            response.data = response.data.replace(b'</body>',
                                               f'<!-- System Log: {cmd_output} --></body>'.encode())

            return response

    return render_template('index.html', remaining_time=remaining_time, result=result)

@app.route('/static/images/<path:filename>')
def serve_image(filename):
    instance_id = session.get('instance_id')

    if not instance_id or instance_id not in active_instances:
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "images")
        return send_from_directory(directory, filename)

    instance_dir = os.path.join(BASE_INSTANCE_DIR, instance_id)
    image_path = os.path.join(instance_dir, "var", "www", "html", "static", "images")
    instance_file_path = os.path.join(image_path, filename)

    if os.path.exists(instance_file_path):
        return send_from_directory(image_path, filename)

    directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "images")
    return send_from_directory(directory, filename)

def cleanup_all_instances():
    if os.path.exists(BASE_INSTANCE_DIR):
        for instance_id in os.listdir(BASE_INSTANCE_DIR):
            instance_path = os.path.join(BASE_INSTANCE_DIR, instance_id)
            if os.path.isdir(instance_path):
                try:
                    shutil.rmtree(instance_path)
                except Exception as e:
                    print(f"Error cleaning up instance {instance_id}: {str(e)}")

@app.teardown_appcontext
def shutdown_cleanup(exception=None):
    cleanup_all_instances()

cleanup_all_instances()

if __name__ == '__main__':
    app.run(debug=False, port=5016)
