import os
import sqlite3
import requests # Added for making HTTP requests
import openai   # Added for OpenAI integration
import json     # Added for parsing JSON
import datetime # Added for timestamping results
from flask import Flask, render_template, jsonify, request # Added request
from collections import Counter # Still needed for frontend if processing happens there, but not here

app = Flask(__name__)

# --- OpenAI Configuration ---
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    print("Warning: OPENAI_API_KEY environment variable not set. LLM analysis will be skipped.")

# --- Database Configuration ---
# NOTE: Only phishing log table is used now
APP_DIR = os.path.dirname(os.path.abspath(__file__))
print(f'This is the app dir : {APP_DIR}')
#DATABASE_PATH = os.path.abspath(os.path.join(APP_DIR, '..', 'database.db'))
DATABASE_PATH = os.getenv('DATABASE_PATH', '/app/database/database.db')
# You might not need this if the volume mount creates it, but it doesn't hurt.
DATABASE_DIR = os.path.dirname(DATABASE_PATH)
os.makedirs(DATABASE_DIR, exist_ok=True)
PHISHING_DB_TABLE_NAME = "phishing_log"
# ANALYSIS_DB_TABLE_NAME = "attack_analysis_log" # REMOVED - Not storing analysis

# --- PHP Log Source URL ---
# This is currently bypassed by the static data below
LOG_SOURCE_URL = "http://host.docker.internal/hackerthon/log_request.php"

# --- Helper Functions ---

def get_db_connection():
    """Creates a connection to the SQLite database (for phishing log)."""
    try:
        if not os.path.exists(DATABASE_PATH):
            print(f"Warning: Database file not found at {DATABASE_PATH}. Will attempt to create.")
            os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        print(f"Database connection successful to {DATABASE_PATH}")
        # Ensure ONLY phishing table exists
        create_phishing_table(conn)
        # create_analysis_table(conn) # REMOVED
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error connecting to database: {e}")
        return None

def create_phishing_table(conn):
    """Creates the phishing_log table if it doesn't exist."""
    try:
        cursor = conn.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {PHISHING_DB_TABLE_NAME} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                sender TEXT,
                subject TEXT
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating table {PHISHING_DB_TABLE_NAME}: {e}")

# def create_analysis_table(conn): # REMOVED - Not storing analysis
#     pass

def analyze_payload_with_llm(payload):
    """
    Analyzes a payload using OpenAI to identify attack type and get recommendations.
    (Function logic remains the same)
    """
    if not openai.api_key:
        print("Skipping LLM analysis: OpenAI API key not configured.")
        return "Error: API Key Missing", "OpenAI API Key not configured."
    try:
        payload_str = str(payload)[:2000]
        prompt = f"""
        Analyze the following data payload received by a web application.
        Identify the specific type of web security attack it represents (e.g., SQL Injection, Cross-Site Scripting (XSS), Command Injection, Path Traversal, Benign/Informational, Reconnaissance).
        If an attack is identified, provide a brief, actionable security recommendation (1-2 sentences) for developers to prevent this type of attack in the future.

        Payload:
        ```
        {payload_str}
        ```

        Respond ONLY with a valid JSON object containing two keys: "attack_type" (string) and "recommendation" (string).
        Example for SQLi: {{"attack_type": "SQL Injection", "recommendation": "Use parameterized queries or prepared statements to prevent SQL injection vulnerabilities."}}
        Example for benign: {{"attack_type": "Benign/Informational", "recommendation": "No specific attack detected in this payload."}}
        """
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful security analysis assistant. Respond ONLY with the requested JSON object."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3, max_tokens=150, response_format={"type": "json_object"}
        )
        content = response.choices[0].message.content
        analysis_result = json.loads(content)
        attack_type = analysis_result.get("attack_type", "Analysis Error")
        recommendation = analysis_result.get("recommendation", "Could not generate recommendation.")
        if not isinstance(attack_type, str) or not isinstance(recommendation, str):
             print(f"LLM returned unexpected types: {analysis_result}")
             return "LLM Response Format Error", "Invalid data types in AI response."
        return attack_type, recommendation
    except openai.OpenAIError as e:
        print(f"OpenAI API error: {e}")
        return "LLM Error", f"OpenAI API Error: {e}"
    except json.JSONDecodeError as e:
        print(f"Error decoding LLM JSON response: {e}")
        print(f"LLM Raw Output was: {content}")
        return "LLM Response Format Error", "Could not parse the analysis result from the AI."
    except Exception as e:
        print(f"Unexpected error during LLM analysis: {e}")
        return "Analysis Error", f"An unexpected error occurred: {e}"

# --- Existing Routes ---

@app.route("/")
def home():
    """Serves the main dashboard HTML page."""
    return render_template("./index.html")

# --- Phishing Data Routes (Unaffected) ---

@app.route("/iam_dashboard")
def iam_dashboard():
    return render_template('./IAM.html')

@app.route("/api/metrics")
def get_metrics():
    """API endpoint to get the count of phishing emails."""
    conn = get_db_connection()
    phishing_count = 0
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {PHISHING_DB_TABLE_NAME}")
            result = cursor.fetchone()
            if result: phishing_count = result[0]
        except sqlite3.Error as e: print(f"Error fetching metrics: {e}")
        except Exception as e: print(f"Unexpected error fetching metrics: {e}")
        finally:
            if conn: conn.close()
    # NOTE: Active threats count is now calculated on the frontend from analysis results
    return jsonify({'phishing_emails_count': phishing_count})

@app.route("/api/phishing-data")
def get_phishing_data():
    """API endpoint to get recent phishing email details."""
    conn = get_db_connection()
    emails = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(f"SELECT timestamp, sender, subject FROM {PHISHING_DB_TABLE_NAME} ORDER BY timestamp DESC LIMIT 15")
            rows = cursor.fetchall()
            emails = [dict(row) for row in rows]
        except sqlite3.Error as e: print(f"Error fetching phishing data: {e}")
        except Exception as e: print(f"Unexpected error fetching phishing data: {e}")
        finally:
             if conn: conn.close()
    return jsonify(emails)

# --- Route to Trigger Analysis (Modified to return results, no DB storage) ---

@app.route("/api/analyze-security-logs", methods=['POST'])
def analyze_security_logs():
    """
    Fetches logs (CURRENTLY USING STATIC DATA), analyzes them using LLM,
    and returns the analysis results directly. Does NOT store results in DB.
    """
    print("Received request to analyze security logs (USING STATIC DATA, ON-THE-FLY)...")
    logs_data = []
    analysis_results = [] # List to hold results
    error_count = 0
    skipped_count = 0

    # --- START: Using Static Data ---
    static_log_data = [
        {"origin":"login","payload":"admin","ip":"127.0.0.1"},
        {"origin":"login","payload":"' OR '1'='1","ip":"127.0.0.1"},
        {"origin":"login","payload":"'","ip":"127.0.0.1"},
        {"origin":"login","payload":"admin' --","ip":"127.0.0.1"},
        {"origin":"login","payload":"admin'-- -","ip":"127.0.0.1"},
        {"origin":"login","payload":"' OR IF(1=1, SLEEP(5), 0)-- -","ip":"127.0.0.1"},
        {"origin":"login","payload":"admin' OR IF(1=1, SLEEP(5), 0)-- -","ip":"127.0.0.1"},
        {"origin":"login","payload":"' AND 1=CONVERT(int, (SELECT @@version))-- -","ip":"127.0.0.1"},
        {"origin":"login","payload":"' ; DROP TABLE users-- -","ip":"127.0.0.1"},
        {"origin":"login","payload":"' AND 1=1-- -","ip":"127.0.0.1"},
        {"origin":"login","payload":"' AND 1=1#","ip":"127.0.0.1"},
        {"origin":"login","payload":"admin","ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":"hello","ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":"hi","ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":"<script","ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":"<script>alert('XSS')</script>","ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<img src="x" onerror="alert(\'XSS\')">',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<input type="text" value="<script>alert(\'XSS\');</script>">',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<a href="#" onclick="alert(\'XSS\')">Click me</a>',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<a href="javascript:alert(\'XSS\')">Click me</a>',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<img src="javascript:alert(\'XSS\')">',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<img src="x&#115;&#99;ript:alert(\'XSS\')">',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<iframe src="javascript:alert(\'XSS\')"></iframe>',"ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<div style="width: expression(alert(\'XSS\'))">Test</div>',"ip":"127.0.0.1"}
    ]
    logs_data = static_log_data
    print(f"Using {len(logs_data)} static log entries for analysis.")
    #--- END: Using Static Data ---

    # --- COMMENTED OUT: Fetching data from the PHP script ---
    # try:
    #     print(f"Fetching logs from {LOG_SOURCE_URL}...")
    #     response = requests.get(LOG_SOURCE_URL, timeout=20) # Increased timeout
    #     response.raise_for_status()
    #     logs_data = response.json()
    #     print(f"Successfully fetched {len(logs_data)} log entries.")
    # except requests.exceptions.RequestException as e:
    #     print(f"Error fetching logs from {LOG_SOURCE_URL}: {e}")
    #     return jsonify({"status": "error", "message": f"Could not fetch logs: {e}"}), 500
    # except json.JSONDecodeError as e:
    #     print(f"Error decoding JSON response from {LOG_SOURCE_URL}: {e}")
    #     print(f"Raw response text: {response.text}")
    #     return jsonify({"status": "error", "message": "Invalid JSON received from log source."}), 500
    # except Exception as e:
    #     print(f"Unexpected error during log fetching: {e}")
    #     return jsonify({"status": "error", "message": f"An unexpected error occurred during fetch: {e}"}), 500
    
    # --- END OF COMMENTED OUT SECTION ---

    if not logs_data or not isinstance(logs_data, list):
        print("No valid log data found or incorrect format.")
        # Return empty list if no data, frontend should handle this
        return jsonify([]), 200

    # --- REMOVED: Database Connection for analysis log ---

    # Process each log entry
    for entry in logs_data:
        try:
            if not isinstance(entry, dict):
                print(f"Skipping invalid log entry (not a dict): {entry}")
                skipped_count += 1
                continue

            origin = entry.get("origin")
            payload = entry.get("payload")
            ip = entry.get("ip")

            if not payload:
                skipped_count += 1
                continue

            # Analyze with LLM
            attack_type, recommendation = analyze_payload_with_llm(payload)

            # Add result to the list
            analysis_results.append({
                "timestamp": datetime.datetime.now().isoformat(), # Add analysis timestamp
                "origin": origin,
                "ip": ip,
                "payload": payload,
                "attack_type": attack_type, # Renamed for clarity
                "recommendation": recommendation
            })

        except Exception as e:
            # Log error for this specific entry and continue if possible
            print(f"Error processing entry {entry}: {e}")
            error_count += 1
            # Optionally add an error entry to results
            analysis_results.append({
                "timestamp": datetime.datetime.now().isoformat(),
                "origin": entry.get("origin", "Unknown"),
                "ip": entry.get("ip", "Unknown"),
                "payload": entry.get("payload", "Unknown"),
                "attack_type": "Processing Error",
                "recommendation": f"Error during analysis: {e}"
            })


    print(f"Finished processing logs on-the-fly. Results generated: {len(analysis_results)}, Skipped: {skipped_count}, Errors during processing: {error_count}")

    # Return the list of analysis results
    return jsonify(analysis_results), 200


# --- REMOVED: API Endpoints for Retrieving Stored Analysis Data ---
# /api/attack-analysis/summary
# /api/attack-analysis/recent
# /api/attack-analysis/recommendations


# --- Main Execution ---

if __name__ == "__main__":
    print("Starting Flask development server...")
    # Ensure only necessary DB table is checked/created on startup
    init_conn = get_db_connection()
    if init_conn: init_conn.close()
    else: print("CRITICAL: Failed to establish initial database connection.")

    app.run(host='0.0.0.0', port=5000, debug=True)
