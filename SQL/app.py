import os
import time
import sqlite3
import random
import re
import uuid
import shutil
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response

app = Flask(__name__)
app.secret_key = '4nc13nt_3gypt11n_53cr3t_k3y'

# Database directory for per-user databases
DB_DIR = 'user_databases'

# Clean up any existing databases on startup
if os.path.exists(DB_DIR):
    shutil.rmtree(DB_DIR)
    
os.makedirs(DB_DIR, exist_ok=True)

# Session timeout in seconds (1 hour)
SESSION_TIMEOUT = 3600

# Blacklist for SQL injection in the soldier dashboard
BLACKLIST = ["UNION", "union", "SELECT", "select", "AND", "and", "FROM", "from", "null", "NULL"]

# Check if session needs to be reset
def check_session_timeout():
    # Check if session needs to be initialized
    if 'user_db_id' not in session or 'session_start_time' not in session:
        reset_user_session()
        return False
        
    # Check if session has expired
    current_time = time.time()
    session_age = current_time - session['session_start_time']
    
    if session_age > SESSION_TIMEOUT:
        # Session has expired
        reset_user_session(expired=True)
        return True
    
    # Calculate remaining time (for server-side tracking)
    session['time_remaining'] = SESSION_TIMEOUT - session_age
    return False

# Reset user session
def reset_user_session(expired=False):
    # If there was a previous session, try to delete the database
    if 'user_db_id' in session:
        try:
            user_dir = os.path.join(DB_DIR, session['user_db_id'])
            if os.path.exists(user_dir):
                shutil.rmtree(user_dir)
        except Exception as e:
            print(f"Error removing database directory: {e}")
    
    # Create new session
    session['user_db_id'] = str(uuid.uuid4())
    session['session_start_time'] = time.time()
    session['time_remaining'] = SESSION_TIMEOUT
    
    # Ensure session is saved
    session.modified = True
    
    # If this was an expiration, set a flash message
    if expired:
        flash("Session time limit reached. A new session has been started.", "warning")

# Function to check for blacklisted SQL injection words
def contains_blacklisted_word(query):
    for word in BLACKLIST:
        if word in query:
            return True
    return False

# Get user-specific database connection
def get_db(environment='soldier'):
    # Check if session has timed out
    check_session_timeout()
    
    # Construct the database path for this user
    user_dir = os.path.join(DB_DIR, session['user_db_id'])
    os.makedirs(user_dir, exist_ok=True)
    
    # Use separate database files for each environment
    db_path = os.path.join(user_dir, f"{environment}.db")
    
    # If the database doesn't exist yet, initialize it
    if not os.path.exists(db_path):
        init_db(db_path, environment)
    
    # Connect to the specific database
    conn = sqlite3.connect(db_path)
    
    # Allow multiple statements to be executed
    conn.isolation_level = None
    
    # Enable row factory for dictionary-like access
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database with unique path and separate environments
def init_db(db_path, environment='soldier'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    if environment == 'soldier':
        # Drop tables first to ensure clean state
        cursor.execute('DROP TABLE IF EXISTS workers')
        cursor.execute('DROP TABLE IF EXISTS soldiers')
        cursor.execute('DROP TABLE IF EXISTS pharaohs_secret')
        cursor.execute('DROP TABLE IF EXISTS soldier_schema_tables')
        cursor.execute('DROP TABLE IF EXISTS soldier_schema_columns')
        
        # Create workers table
        cursor.execute('''
        CREATE TABLE workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'worker'
        )
        ''')
        
        # Create soldiers table
        cursor.execute('''
        CREATE TABLE soldiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            rank TEXT NOT NULL,
            strength INTEGER NOT NULL,
            loyalty TEXT NOT NULL
        )
        ''')
        
        # Create pharaohs_secret table for credentials discovery
        cursor.execute('''
        CREATE TABLE pharaohs_secret (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            access_level TEXT NOT NULL
        )
        ''')
        
        # Insert pharaoh credentials
        cursor.execute("INSERT INTO pharaohs_secret (username, access_level) VALUES ('khufu', 'pharaoh')")
        
        # Create a special fake table to simulate information_schema.tables
        cursor.execute('''
        CREATE TABLE soldier_schema_tables (
            table_name TEXT PRIMARY KEY
        )
        ''')
        
        # Populate the fake schema table with visible tables
        tables = [
            ('workers',),
            ('soldiers',),
            ('pharaohs_secret',)
        ]
        
        for table in tables:
            cursor.execute("INSERT INTO soldier_schema_tables (table_name) VALUES (?)", table)
            
        # Create a special fake table to simulate information_schema.columns
        cursor.execute('''
        CREATE TABLE soldier_schema_columns (
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            PRIMARY KEY (table_name, column_name)
        )
        ''')
        
        # Add columns for tables
        columns_data = [        
            # soldiers columns
            ('soldiers', 'id'),
            ('soldiers', 'name'),
            ('soldiers', 'rank'),
            ('soldiers', 'strength'),
            ('soldiers', 'loyalty'),
            
            # workers columns
            ('workers', 'id'),
            ('workers', 'username'),
            ('workers', 'password'),
            ('workers', 'role'),
            
            # pharaohs_secret columns
            ('pharaohs_secret', 'id'),
            ('pharaohs_secret', 'username'),
            ('pharaohs_secret', 'access_level')
        ]
        
        for column in columns_data:
            cursor.execute("INSERT INTO soldier_schema_columns (table_name, column_name) VALUES (?, ?)", column)
        
        # Add a soldier account
        cursor.execute("INSERT INTO workers (username, password, role) VALUES ('soldier', 'warrior_of_ra', 'soldier')")
        
        # Add some regular soldiers
        soldiers_data = [
            ('ramses', 'regular', 75, 'high'),
            ('neferu', 'archer', 65, 'medium'),
            ('khonsu', 'charioteer', 80, 'high'),
            ('sebek', 'elite', 90, 'absolute'),
            ('tauret', 'regular', 70, 'medium')
        ]
        for soldier in soldiers_data:
            cursor.execute("INSERT INTO soldiers (name, rank, strength, loyalty) VALUES (?, ?, ?, ?)", soldier)
        
        # Add more workers
        workers_data = [
            ('stonecutter1', 'build123', 'worker'),
            ('water_bearer', 'nile_flow', 'worker'),
            ('pyramid_builder', 'giza123', 'worker')
        ]
        for worker in workers_data:
            cursor.execute("INSERT INTO workers (username, password, role) VALUES (?, ?, ?)", worker)
    
    elif environment == 'pharaoh':
        # Initialize pharaoh environment
        cursor.execute('DROP TABLE IF EXISTS pharaohs')
        cursor.execute('DROP TABLE IF EXISTS sacred_deities')
        cursor.execute('DROP TABLE IF EXISTS users')  # Add users table for easier SQL injection
        cursor.execute('DROP TABLE IF EXISTS pharaoh_credentials')
        cursor.execute('DROP TABLE IF EXISTS pharaoh_schema_tables')
        cursor.execute('DROP TABLE IF EXISTS pharaoh_schema_columns')
        
        # Create pharaohs table
        cursor.execute('''
        CREATE TABLE pharaohs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            access_level TEXT NOT NULL
        )
        ''')
        
        # Create pharaoh_credentials table for actual login validation
        cursor.execute('''
        CREATE TABLE pharaoh_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            access_level TEXT NOT NULL
        )
        ''')
        
        # Insert the same credentials for login validation
        cursor.execute("INSERT INTO pharaoh_credentials (username, access_level) VALUES ('khufu', 'pharaoh')")
        
        # Create sacred_deities table
        cursor.execute('''
        CREATE TABLE sacred_deities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            power TEXT NOT NULL,
            secret_code TEXT
        )
        ''')
        
        # Create users table (for simpler SQL injection targets)
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL
        )
        ''')
        
        # Add the hidden god - duplicate to both tables
        cursor.execute("INSERT INTO sacred_deities (name, power, secret_code) VALUES ('amuntekh', 'ultimate', 'm4st3r_g0d}')")
        cursor.execute("INSERT INTO users (name, role) VALUES ('amuntekh', 'god')")
        
        # Add decoy gods
        gods_data = [
            ('ra', 'sun', 'not_the_flag'),
            ('anubis', 'death', 'not_the_flag'),
            ('isis', 'magic', 'not_the_flag'),
            ('osiris', 'afterlife', 'not_the_flag'),
            ('seth', 'chaos', 'not_the_flag')
        ]
        for god in gods_data:
            cursor.execute("INSERT INTO sacred_deities (name, power, secret_code) VALUES (?, ?, ?)", god)
            cursor.execute("INSERT INTO users (name, role) VALUES (?, ?)", (god[0], 'deity'))
            
        # Create a special fake table for pharaoh dashboard environment
        cursor.execute('''
        CREATE TABLE pharaoh_schema_tables (
            table_name TEXT PRIMARY KEY
        )
        ''')
        
        # Populate the pharaoh schema with different tables
        pharaoh_tables = [
            ('sacred_deities',),
            ('pharaohs',),
            ('users',)  # Add users table to schema
        ]
        
        for table in pharaoh_tables:
            cursor.execute("INSERT INTO pharaoh_schema_tables (table_name) VALUES (?)", table)

        # Create columns for pharaoh schema
        cursor.execute('''
        CREATE TABLE pharaoh_schema_columns (
            table_name TEXT NOT NULL,
            column_name TEXT NOT NULL,
            PRIMARY KEY (table_name, column_name)
        )
        ''')
        
        # Add columns for pharaoh dashboard tables
        pharaoh_columns_data = [
            # sacred_deities columns
            ('sacred_deities', 'id'),
            ('sacred_deities', 'name'),
            ('sacred_deities', 'power'),
            ('sacred_deities', 'secret_code'),
            
            # pharaohs columns
            ('pharaohs', 'id'),
            ('pharaohs', 'name'),
            ('pharaohs', 'access_level'),
            
            # users columns
            ('users', 'id'),
            ('users', 'name'),
            ('users', 'role')
        ]
        
        for column in pharaoh_columns_data:
            cursor.execute("INSERT INTO pharaoh_schema_columns (table_name, column_name) VALUES (?, ?)", column)
    
    # Commit all changes and close
    conn.commit()
    conn.close()

# Context processor to add timer data to all templates
@app.context_processor
def inject_timer_data():
    timer_data = {
        'session_timeout': SESSION_TIMEOUT,
        'time_remaining': session.get('time_remaining', SESSION_TIMEOUT)
    }
    return {'timer_data': timer_data}

# Format time remaining for display
@app.template_filter('format_time_remaining')
def format_time_remaining(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    return f"{minutes:02d}:{seconds:02d}"

# Before request handler to check session timeout
@app.before_request
def before_request():
    # Skip for static files
    if request.path.startswith('/static/'):
        return
    
    # Check session timeout
    check_session_timeout()

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Worker login route - vulnerable to SQL injection
@app.route('/worker/login', methods=['GET', 'POST'])
def worker_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db('soldier')
        cursor = conn.cursor()
        
        # Vulnerable SQL query - allows login bypass
        query = f"SELECT * FROM workers WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['logged_in'] = True
                session['username'] = user['username']
                session['role'] = user['role']
                
                # Flag for soldier role
                if user['role'] == 'soldier':
                    flash('Welcome, brave soldier! Here is your first haft of the reward: O24{1nj3c10n_', 'success')
                else:
                    flash(f'Welcome back, {user["username"]}!', 'success')
                
                return redirect(url_for(f"{user['role']}_dashboard"))
            else:
                flash('Invalid credentials', 'error')
        except sqlite3.Error as e:
            flash(f'Error: {e}', 'error')
        finally:
            conn.close()
            
    return render_template('worker_login.html')

# Worker registration
@app.route('/worker/register', methods=['GET', 'POST'])
def worker_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db('soldier')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO workers (username, password, role) VALUES (?, ?, 'worker')", 
                          (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('worker_login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
        finally:
            conn.close()
            
    return render_template('worker_register.html')

# Pharaoh login route
@app.route('/pharaoh/login', methods=['GET', 'POST'])
def pharaoh_login():
    if request.method == 'GET':
        return render_template('pharaoh_login.html')
    
    name = request.form.get('name')
    access_level = request.form.get('access_level')
    
    # Debug information
    print(f"Attempting pharaoh login with: name='{name}', access_level='{access_level}'")
    
    conn = get_db('pharaoh')
    cursor = conn.cursor()
    
    try:
        # Check for the specific pharaoh using the pharaoh_credentials table
        cursor.execute("SELECT * FROM pharaoh_credentials WHERE username = ? AND access_level = ?", 
                    (name, access_level))
        pharaoh = cursor.fetchone()
        
        if pharaoh:
            session['logged_in'] = True
            session['username'] = pharaoh['username']
            session['role'] = 'pharaoh'
            return redirect('/pharaoh/dashboard')
        else:
            return render_template('pharaoh_login.html', error="Invalid credentials - No pharaoh found with the provided name and access level")
    except Exception as e:
        return render_template('pharaoh_login.html', error=f"An error occurred: {str(e)}")
    finally:
        conn.close()

# Worker dashboard
@app.route('/worker/dashboard')
def worker_dashboard():
    if not session.get('logged_in') or session.get('role') != 'worker':
        flash('You must be logged in as a worker')
        return redirect(url_for('worker_login'))
        
    tasks = [
        "Water the sacred elephants",
        "Carry stone blocks for the pyramids",
        "Polish the pharaoh's golden statues",
        "Harvest papyrus from the Nile",
        "Feed the sacred cats"
    ]
    
    return render_template('worker_dashboard.html', tasks=tasks)

# Soldier dashboard - has SQL injectable search function
@app.route('/soldier/dashboard')
def soldier_dashboard():
    if not session.get('logged_in') or session.get('role') != 'soldier':
        flash('You must be logged in as a soldier')
        return redirect(url_for('worker_login'))
    
    conn = get_db('soldier')
    cursor = conn.cursor()
    
    # Get worker stats
    cursor.execute("SELECT COUNT(*) as count FROM workers WHERE role = 'worker'")
    worker_count = cursor.fetchone()['count']
    
    cursor.execute("SELECT COUNT(*) as count FROM soldiers")
    soldier_count = cursor.fetchone()['count']
    
    # Construction progress (random for flavor)
    progress = random.randint(65, 95)
    
    conn.close()
    
    return render_template('soldier_dashboard.html', 
                          worker_count=worker_count,
                          soldier_count=soldier_count,
                          progress=progress)

@app.route('/soldier/search', methods=['GET', 'POST'])
def soldier_search():
    if not session.get('logged_in') or session.get('role') != 'soldier':
        return jsonify({'error': 'Unauthorized'}), 403
    
    search_term = request.form.get('search', '')
    
    # Check for blacklisted words
    if contains_blacklisted_word(search_term):
        return jsonify({'error': 'Invalid search term detected'}), 403
    
    conn = get_db('soldier')
    cursor = conn.cursor()
    
    # Modified to support realistic SQL injection discovery
    query = f"SELECT id, name, rank, strength FROM soldiers WHERE name LIKE '%{search_term}%'"
    
    try:
        print(f"Original search query: {query}")
        
        # For table discovery (information_schema.tables)
        if "information_schema.tables" in search_term.lower():
            print("Student is attempting to discover tables")
            query = query.replace("information_schema.tables", "soldier_schema_tables")
        
        # For column discovery (information_schema.columns)
        elif "information_schema.columns" in search_term.lower() or "information_schema.column" in search_term.lower():
            print("Student is attempting to discover columns")
            # Fix the singular/plural issue
            query = query.replace("information_schema.columns", "soldier_schema_columns")
            query = query.replace("information_schema.column", "soldier_schema_columns")
        
        # The query can run as-is for direct table access - let SQL handle it
        print(f"Modified query to execute: {query}")
        cursor.execute(query)
        results = cursor.fetchall()
        
        soldiers = []
        for row in results:
            soldier = {}
            for key in row.keys():
                soldier[key] = row[key]
            soldiers.append(soldier)
            
        return jsonify({'soldiers': soldiers})
    except sqlite3.Error as e:
        error_msg = str(e)
        full_error = f"Error in query: {query}. Details: {error_msg}"
        return jsonify({'error': full_error}), 500
    finally:
        conn.close()

# Pharaoh dashboard with the final god challenge
@app.route('/pharaoh/dashboard')
def pharaoh_dashboard():
    if not session.get('logged_in') or session.get('role') != 'pharaoh':
        flash('You must be logged in as the pharaoh')
        return redirect(url_for('worker_login'))
    
    # Add a hint message about the deity challenge
    hint = "The Oracle searches for deities by name... one character at a time. Some say the users table holds a secret deity."
    
    return render_template('pharaoh_dashboard.html', hint=hint)

# Enhanced God search endpoint - vulnerable to time-based blind SQL injection with broader pattern support
@app.route('/pharaoh/search_deity', methods=['GET'])
def search_deity():
    if not session.get('logged_in') or session.get('role') != 'pharaoh':
        return jsonify({'error': 'Unauthorized'}), 403
    
    deity_name = request.args.get('name', '')
    print(f"Deity search query: {deity_name}")
    
    # The hidden deity we want students to find
    hidden_deity = "amuntekh"
    
    # Convert to lowercase for case-insensitive matching
    query_lower = deity_name.lower()
    
    
    # Track if this is a valid SQL injection attempt for blind testing
    is_valid_pattern = False
    position = None
    test_char = None
    
    # Detect position parameter in various forms
    pos_patterns = [
        # Basic substr patterns
        r'substr\s*\(\s*name\s*,\s*(\d+)',
        r'substring\s*\(\s*name\s*,\s*(\d+)',
        r'mid\s*\(\s*name\s*,\s*(\d+)',
        
        # Nested select substr patterns
        r'substr\s*\(\s*\(\s*select\s+name.*?\)\s*,\s*(\d+)',
        r'substring\s*\(\s*\(\s*select\s+name.*?\)\s*,\s*(\d+)',
        r'substr\s*\(\s*select\s+name.*?\s*,\s*(\d+)',
        r'substring\s*\(\s*select\s+name.*?\s*,\s*(\d+)',
        
        # ASCII function patterns
        r'ascii\s*\(\s*substr\s*\(\s*name\s*,\s*(\d+)',
        r'ascii\s*\(\s*substring\s*\(\s*name\s*,\s*(\d+)',
        r'ascii\s*\(\s*substr\s*\(\s*\(\s*select\s+name.*?\)\s*,\s*(\d+)',
        r'ascii\s*\(\s*substring\s*\(\s*\(\s*select\s+name.*?\)\s*,\s*(\d+)',
        
        # Complex patterns with SELECT
        r'select\s+substr\s*\(\s*name\s*,\s*(\d+)',
        r'select\s+substring\s*\(\s*name\s*,\s*(\d+)',
        r'select\s+ascii\s*\(\s*substr\s*\(\s*name\s*,\s*(\d+)',
        r'select\s+ascii\s*\(\s*substring\s*\(\s*name\s*,\s*(\d+)',
    ]
    
    # Try to extract position
    for pattern in pos_patterns:
        match = re.search(pattern, query_lower, re.IGNORECASE)
        if match:
            try:
                position = int(match.group(1))
                is_valid_pattern = True
                break
            except (ValueError, IndexError):
                continue
    
    # For LIKE/GLOB patterns with position in first character
    like_patterns = [
        r"name\s+like\s+['\"]([a-zA-Z0-9])",
        r"name\s+glob\s+['\"]([a-zA-Z0-9])",
        r"select\s+name.*?\s+like\s+['\"]([a-zA-Z0-9])",
        r"select\s+name.*?\s+glob\s+['\"]([a-zA-Z0-9])",
    ]
    
    if position is None:
        for pattern in like_patterns:
            match = re.search(pattern, query_lower, re.IGNORECASE)
            if match:
                try:
                    test_char = match.group(1).lower()
                    position = 1  # LIKE 'a%' tests first character
                    is_valid_pattern = True
                    break
                except (ValueError, IndexError):
                    continue
    
    # Step 2: Find the character being tested (if not found in LIKE patterns)
    if position is not None and test_char is None:
        # Direct comparison patterns
        char_patterns = [
            r"=\s*['\"]([a-zA-Z0-9])['\"]",  # Basic equality
            r"=\s*char\s*\(\s*(\d+)\s*\)",   # CHAR() function
        ]
        
        for pattern in char_patterns:
            match = re.search(pattern, query_lower, re.IGNORECASE)
            if match:
                try:
                    # Direct character or char(xx) function
                    if match.group(1).isdigit():
                        # It's a CHAR() function with ASCII value
                        ascii_value = int(match.group(1))
                        test_char = chr(ascii_value).lower()
                    else:
                        # It's a direct character
                        test_char = match.group(1).lower()
                    break
                except (ValueError, IndexError):
                    continue
        
        # ASCII value comparison patterns (e.g. ASCII(...) = 97)
        ascii_patterns = [
            r"=\s*(\d+)",  # Direct number comparison after ASCII function
        ]
        
        if test_char is None and "ascii" in query_lower:
            for pattern in ascii_patterns:
                match = re.search(pattern, query_lower, re.IGNORECASE)
                if match:
                    try:
                        ascii_value = int(match.group(1))
                        # Convert ASCII value to character
                        if 32 <= ascii_value <= 126:  # Printable ASCII range
                            test_char = chr(ascii_value).lower()
                            break
                    except (ValueError, IndexError):
                        continue
    
    if "case when" in query_lower or "iif" in query_lower:
        # First extract position from the CASE/IIF statement
        case_pos_patterns = [
            r"substr\s*\(\s*name\s*,\s*(\d+).+?case\s+when",
            r"substring\s*\(\s*name\s*,\s*(\d+).+?case\s+when",
            r"case\s+when.+?substr\s*\(\s*name\s*,\s*(\d+)",
            r"case\s+when.+?substring\s*\(\s*name\s*,\s*(\d+)",
            r"iif\s*\(.+?substr\s*\(\s*name\s*,\s*(\d+)",
            r"iif\s*\(.+?substring\s*\(\s*name\s*,\s*(\d+)",
        ]
        
        for pattern in case_pos_patterns:
            match = re.search(pattern, query_lower, re.IGNORECASE)
            if match:
                try:
                    position = int(match.group(1))
                    is_valid_pattern = True
                    break
                except (ValueError, IndexError):
                    continue
        
        # Then extract character from the CASE/IIF statement
        case_char_patterns = [
            r"=\s*['\"]([a-zA-Z0-9])['\"]",
        ]
        
        for pattern in case_char_patterns:
            match = re.search(pattern, query_lower, re.IGNORECASE)
            if match:
                try:
                    test_char = match.group(1).lower()
                    break
                except (ValueError, IndexError):
                    continue
    
    if "exists" in query_lower and (position is None or test_char is None):
        exists_patterns = [
            r"name\s+like\s+['\"]([a-zA-Z0-9])%",
        ]
        
        for pattern in exists_patterns:
            match = re.search(pattern, query_lower, re.IGNORECASE)
            if match:
                try:
                    test_char = match.group(1).lower()
                    position = 1  # EXISTS with LIKE 'a%' tests first character
                    is_valid_pattern = True
                    break
                except (ValueError, IndexError):
                    continue
    
    print(f"Parsed position: {position}, character: {test_char}, valid pattern: {is_valid_pattern}")
    
    # If we successfully parsed a position and character, evaluate the injection
    if position is not None and test_char is not None and is_valid_pattern:
        if position <= len(hidden_deity) and hidden_deity[position-1].lower() == test_char:
            print(f"SUCCESS: Character at position {position} is '{test_char}'")
            # Add a noticeable delay for time-based detection
            time.sleep(3)  # 3 second delay makes it more obvious
            return jsonify({
                'deities': [],
                'message': 'The Oracle pauses... a powerful presence is felt. Your question touches truth.',
                'hint': f'When you find each character, remember to build the name one letter at a time...',
                'response_time': 'slow'  # Extra hint about the time-based nature
            })
        else:
            print(f"FAIL: Character at position {position} is not '{test_char}'")
            return jsonify({
                'deities': [],
                'message': 'The Oracle responds quickly. Nothing of interest is found.',
                'response_time': 'fast'  # Extra hint about the time-based nature
            })
    
    # If it's not a recognized blind SQL pattern, return a normal response
    return jsonify({
        'deities': [],
        'message': 'The Oracle awaits your question about the hidden deity.',
        'hint': 'Try using SQL to reveal the deity in the users table, one character at a time...'
    })

# Endpoint to attempt to become a god
@app.route('/pharaoh/become_deity', methods=['POST'])
def become_deity():
    if not session.get('logged_in') or session.get('role') != 'pharaoh':
        return jsonify({'error': 'Unauthorized'}), 403
    
    deity_name = request.form.get('deity_name', '')
    print(f"Attempting to become deity: {deity_name}")
    
    conn = get_db('pharaoh')
    cursor = conn.cursor()
    
    try:
        # Check if this is the secret deity
        cursor.execute("SELECT * FROM sacred_deities WHERE name = ?", (deity_name,))
        deity = cursor.fetchone()
        
        if deity and deity['name'] == 'amuntekh':
            # They found the secret god!
            print(f"Success! User found the hidden deity: {deity_name}")
            return jsonify({
                'success': True,
                'message': 'You have transcended humanity and become a god!',
                'flag': 'm4st3r_g0d}'
            })
        else:
            print(f"Failed attempt with deity: {deity_name}")
            return jsonify({
                'success': False,
                'message': 'The ritual failed. This deity cannot be embodied by mortals.'
            })
    except sqlite3.Error as e:
        print(f"SQL Error in become_deity: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/view-source/<path:route_path>')
def view_source(route_path):
    # Return the template directly without authentication
    try:
        return render_template(f"{route_path}.html")
    except:
        return "Template not found", 404

# Add custom HTTP headers with expanded hints
@app.after_request
def add_header(response):
    response.headers['X-Ancient-Scroll'] = 'The truth often lies in equality'
    response.headers['X-Sacred-Knowledge'] = 'When searching for soldiers, look beyond what is visible'
    response.headers['X-Oracle-Wisdom'] = 'The users table holds secrets. Query its name one letter at a time.'
    return response

# Function to clean up old databases
def cleanup_old_databases():
    """Clean up databases that haven't been accessed in more than 24 hours"""
    current_time = time.time()
    for user_dir in os.listdir(DB_DIR):
        user_path = os.path.join(DB_DIR, user_dir)
        if os.path.isdir(user_path):
            # Check the directory modification time
            dir_mod_time = os.path.getmtime(user_path)
            if current_time - dir_mod_time > 86400:
                try:
                    shutil.rmtree(user_path)
                    print(f"Removed old database directory: {user_dir}")
                except Exception as e:
                    print(f"Error removing old database directory {user_dir}: {e}")

# Schedule cleanup
@app.before_request
def check_cleanup():
    # Skip for static files
    if request.path.startswith('/static/'):
        return
        
    # Run cleanup once every 100 requests
    if random.randint(1, 100) == 1:
        cleanup_old_databases()

if __name__ == '__main__':
    app.run(debug=False, port=5014)
