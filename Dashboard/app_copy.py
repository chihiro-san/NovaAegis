import os
import sqlite3
import requests # Added for making HTTP requests
import openai   # Added for OpenAI integration
import json     # Added for parsing JSON
from flask import Flask, render_template, jsonify, request # Added request
from collections import Counter # Added for counting attack types

app = Flask(__name__)

# --- OpenAI Configuration ---
# IMPORTANT: Load your API key securely from environment variables
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    print("Warning: OPENAI_API_KEY environment variable not set. LLM analysis will be skipped.")
    # Don't exit, allow app to run but LLM features will return errors

# --- Database Configuration ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.abspath(os.path.join(APP_DIR, '..', 'database.db'))
PHISHING_DB_TABLE_NAME = "phishing_log" # Existing table for phishing emails
ANALYSIS_DB_TABLE_NAME = "attack_analysis_log" # New table for attack analysis

# --- PHP Log Source URL ---
LOG_SOURCE_URL = "http://localhost/hackerthon/log_request.php"

# --- Helper Functions ---

def get_db_connection():
    """Creates a connection to the SQLite database."""
    try:
        if not os.path.exists(DATABASE_PATH):
            print(f"Warning: Database file not found at {DATABASE_PATH}. Will attempt to create.")
            os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        # Use check_same_thread=False for simplicity in Flask dev server
        # For production, consider a more robust setup (e.g., request-scoped sessions)
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        print(f"Database connection successful to {DATABASE_PATH}")
        # Ensure tables exist on first connection attempt in a request context potentially
        create_phishing_table(conn)
        create_analysis_table(conn)
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
                -- Add other columns if your original script used them
            )
        """)
        conn.commit()
        # print(f"Table '{PHISHING_DB_TABLE_NAME}' checked/created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating table {PHISHING_DB_TABLE_NAME}: {e}")

def create_analysis_table(conn):
    """Creates the attack_analysis_log table if it doesn't exist."""
    try:
        cursor = conn.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {ANALYSIS_DB_TABLE_NAME} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                origin TEXT,
                ip TEXT,
                payload TEXT,
                identified_attack_type TEXT,
                recommendation TEXT
            )
        """)
        conn.commit()
        # print(f"Table '{ANALYSIS_DB_TABLE_NAME}' checked/created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating table {ANALYSIS_DB_TABLE_NAME}: {e}")

def analyze_payload_with_llm(payload):
    """
    Analyzes a payload using OpenAI to identify attack type and get recommendations.
    Returns: tuple: (attack_type, recommendation) or specific error strings.
    """
    if not openai.api_key:
        print("Skipping LLM analysis: OpenAI API key not configured.")
        return "Error: API Key Missing", "OpenAI API Key not configured."

    try:
        # Ensure payload is a string and not excessively long
        payload_str = str(payload)[:2000] # Limit payload length sent to LLM

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
            model="gpt-3.5-turbo", # Or use "gpt-4" if available/preferred
            messages=[
                {"role": "system", "content": "You are a helpful security analysis assistant. Respond ONLY with the requested JSON object."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3, # Lower temperature for more deterministic response
            max_tokens=150,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content
        analysis_result = json.loads(content)

        attack_type = analysis_result.get("attack_type", "Analysis Error")
        recommendation = analysis_result.get("recommendation", "Could not generate recommendation.")

        # Basic validation
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
            if result:
                phishing_count = result[0]
        except sqlite3.Error as e:
            print(f"Error fetching metrics: {e}")
        except Exception as e:
            print(f"Unexpected error fetching metrics: {e}")
        finally:
            if conn: conn.close() # Close connection
    return jsonify({'phishing_emails_count': phishing_count})

@app.route("/api/phishing-data")
def get_phishing_data():
    """API endpoint to get recent phishing email details."""
    conn = get_db_connection()
    emails = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT timestamp, sender, subject
                FROM {PHISHING_DB_TABLE_NAME}
                ORDER BY timestamp DESC
                LIMIT 15
            """)
            rows = cursor.fetchall()
            emails = [dict(row) for row in rows]
        except sqlite3.Error as e:
            print(f"Error fetching phishing data: {e}")
        except Exception as e:
            print(f"Unexpected error fetching phishing data: {e}")
        finally:
             if conn: conn.close() # Close connection
    return jsonify(emails)

# --- Route to Trigger Analysis ---

@app.route("/api/analyze-security-logs", methods=['POST'])
def analyze_security_logs():
    """
    Fetches logs from PHP source, analyzes them using LLM,
    and stores results in the database.
    """
    print("Received request to analyze security logs...")
    logs_data = []
    processed_count = 0
    error_count = 0
    skipped_count = 0

    # 1. Fetch data from the PHP script
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
    
    # --- START: Using Static Data ---
    # Define the static log data as a Python list of dictionaries
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
        {"origin":"Internal chat app","payload":"<script","ip":"127.0.0.1"}, # Potential incomplete XSS
        {"origin":"Internal chat app","payload":"<script>alert('XSS')</script>","ip":"127.0.0.1"},
        {"origin":"Internal chat app","payload":'<img src="x" onerror="alert(\'XSS\')">',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<input type="text" value="<script>alert(\'XSS\');</script>">',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<a href="#" onclick="alert(\'XSS\')">Click me</a>',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<a href="javascript:alert(\'XSS\')">Click me</a>',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<img src="javascript:alert(\'XSS\')">',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<img src="x&#115;&#99;ript:alert(\'XSS\')">',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<iframe src="javascript:alert(\'XSS\')"></iframe>',"ip":"127.0.0.1"}, # Note: Escaped inner quotes
        {"origin":"Internal chat app","payload":'<div style="width: expression(alert(\'XSS\'))">Test</div>',"ip":"127.0.0.1"} # Note: Escaped inner quotes (CSS Expression - old IE)
    ]

    # Assign the static data to the variable that was previously filled by the fetch
    logs_data = static_log_data
    print(f"Using {len(logs_data)} static log entries for analysis.")
    # --- END: Using Static Data ---


    if not logs_data or not isinstance(logs_data, list):
        print("No valid log data found or incorrect format.")
        return jsonify({"status": "success", "message": "No new valid logs to analyze."}), 200

    # 2. Connect to DB
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection failed."}), 500

    # 3. Process each log entry
    try:
        cursor = conn.cursor()
        for entry in logs_data:
            if not isinstance(entry, dict):
                print(f"Skipping invalid log entry (not a dict): {entry}")
                skipped_count += 1
                continue

            origin = entry.get("origin")
            payload = entry.get("payload")
            ip = entry.get("ip")

            if not payload:
                # print(f"Skipping entry due to missing payload: {entry}") # Reduce noise
                skipped_count += 1
                continue

            # 4. Analyze with LLM
            # print(f"Analyzing payload from {origin} (IP: {ip}): {str(payload)[:50]}...")
            attack_type, recommendation = analyze_payload_with_llm(payload)
            # print(f"Analysis result: Type='{attack_type}', Recommendation='{recommendation[:50]}...'")

            # 5. Store results in DB
            try:
                cursor.execute(
                    f"""
                    INSERT INTO {ANALYSIS_DB_TABLE_NAME} (origin, ip, payload, identified_attack_type, recommendation)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (str(origin), str(ip), str(payload), str(attack_type), str(recommendation)) # Ensure values are strings
                )
                processed_count += 1
            except sqlite3.Error as e:
                print(f"Error inserting analysis result into DB: {e}")
                error_count += 1
            except Exception as e:
                 print(f"Unexpected error inserting analysis result: {e}")
                 error_count += 1

        conn.commit()
        print(f"Finished processing logs. Processed: {processed_count}, Skipped: {skipped_count}, Errors: {error_count}")

    except Exception as e:
        print(f"An error occurred during log processing loop: {e}")
        error_count = len(logs_data) - processed_count - skipped_count # Estimate errors
        return jsonify({
            "status": "error",
            "message": f"An error occurred during processing: {e}",
            "processed": processed_count,
            "skipped": skipped_count,
            "errors": error_count
        }), 500
    finally:
        if conn: conn.close()

    return jsonify({
        "status": "success",
        "message": f"Processed {processed_count} log entries.",
        "skipped": skipped_count,
        "errors": error_count
    }), 200

# --- NEW: API Endpoints to Retrieve Analysis Data ---

@app.route("/api/attack-analysis/summary")
def get_attack_analysis_summary():
    """API endpoint to get counts of identified attack types."""
    conn = get_db_connection()
    summary = []
    if conn:
        try:
            cursor = conn.cursor()
            # Group by identified_attack_type and count occurrences
            cursor.execute(f"""
                SELECT identified_attack_type, COUNT(*) as count
                FROM {ANALYSIS_DB_TABLE_NAME}
                WHERE identified_attack_type IS NOT NULL
                  AND identified_attack_type NOT LIKE 'Error:%' -- Exclude analysis errors
                  AND identified_attack_type NOT LIKE 'LLM%'
                  AND identified_attack_type NOT LIKE 'Analysis Error'
                GROUP BY identified_attack_type
                ORDER BY count DESC
            """)
            rows = cursor.fetchall()
            summary = [dict(row) for row in rows]
        except sqlite3.Error as e:
            print(f"Error fetching attack analysis summary: {e}")
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            print(f"Unexpected error fetching attack summary: {e}")
            return jsonify({"error": "An unexpected error occurred"}), 500
        finally:
            if conn: conn.close()
    else:
        return jsonify({"error": "Database connection failed"}), 500

    # Add status and color heuristically for the frontend
    # (Could be refined or stored in DB later)
    color_map = {
        "SQL Injection": '#f87171', # red-400
        "Cross-Site Scripting (XSS)": '#f87171', # red-400
        "Command Injection": '#f87171', # red-400
        "Path Traversal": '#fb923c', # orange-400
        "Malware Execution": '#fb923c', # orange-400
        "Credential Access": '#fb923c', # orange-400
        "Reconnaissance": '#facc15', # yellow-400
        "Log Tampering": '#a78bfa', # violet-400
        "Benign/Informational": '#4ade80', # green-400
        # Add more as needed
    }
    status_map = {
        "SQL Injection": 'Active',
        "Cross-Site Scripting (XSS)": 'Active',
        "Command Injection": 'Active',
        "Path Traversal": 'Active',
        "Malware Execution": 'Active',
        "Credential Access": 'Active',
        "Reconnaissance": 'Monitoring',
        "Log Tampering": 'Monitoring',
        "Benign/Informational": 'Resolved',
    }
    default_color = '#9ca3af' # gray-400
    default_status = 'Unknown'

    for item in summary:
        attack_type = item.get('identified_attack_type', '')
        item['color'] = color_map.get(attack_type, default_color)
        item['status'] = status_map.get(attack_type, default_status)
        # Rename key for frontend consistency
        item['type'] = item.pop('identified_attack_type')


    return jsonify(summary)


@app.route("/api/attack-analysis/recent")
def get_recent_analysis_logs():
    """API endpoint to get the latest N analyzed log entries."""
    limit = request.args.get('limit', 20, type=int) # Allow specifying limit via query param
    conn = get_db_connection()
    recent_logs = []
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT timestamp, origin, ip, payload, identified_attack_type, recommendation
                FROM {ANALYSIS_DB_TABLE_NAME}
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            recent_logs = [dict(row) for row in rows]
        except sqlite3.Error as e:
            print(f"Error fetching recent analysis logs: {e}")
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            print(f"Unexpected error fetching recent logs: {e}")
            return jsonify({"error": "An unexpected error occurred"}), 500
        finally:
            if conn: conn.close()
    else:
        return jsonify({"error": "Database connection failed"}), 500

    return jsonify(recent_logs)


@app.route("/api/attack-analysis/recommendations")
def get_distinct_recommendations():
    """API endpoint to get distinct AI-generated recommendations."""
    conn = get_db_connection()
    recommendations = []
    if conn:
        try:
            cursor = conn.cursor()
            # Select distinct recommendations, ignoring error/placeholder ones
            cursor.execute(f"""
                SELECT DISTINCT recommendation
                FROM {ANALYSIS_DB_TABLE_NAME}
                WHERE recommendation IS NOT NULL
                  AND recommendation NOT LIKE 'Error:%'
                  AND recommendation NOT LIKE 'LLM%'
                  AND recommendation NOT LIKE 'Analysis Error%'
                  AND recommendation NOT LIKE 'Could not generate%'
                  AND recommendation NOT LIKE 'OpenAI API Key not configured.'
                  AND recommendation NOT LIKE 'No specific attack detected%'
                ORDER BY recommendation ASC
            """)
            rows = cursor.fetchall()
            # Extract the string from each row object
            recommendations = [row['recommendation'] for row in rows]
        except sqlite3.Error as e:
            print(f"Error fetching distinct recommendations: {e}")
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            print(f"Unexpected error fetching recommendations: {e}")
            return jsonify({"error": "An unexpected error occurred"}), 500
        finally:
            if conn: conn.close()
    else:
        return jsonify({"error": "Database connection failed"}), 500

    return jsonify(recommendations)


# --- Main Execution ---

if __name__ == "__main__":
    print("Starting Flask development server...")
    # Ensure database and tables are checked/created on startup
    init_conn = get_db_connection()
    if init_conn:
        # create_phishing_table(init_conn) # Already called in get_db_connection
        # create_analysis_table(init_conn) # Already called in get_db_connection
        init_conn.close()
    else:
        print("CRITICAL: Failed to establish initial database connection.")

    # Use 0.0.0.0 to be accessible within Docker network
    # Use a proper WSGI server (like Gunicorn or Waitress) for production
    app.run(host='0.0.0.0', port=5000, debug=True) # debug=True for development ONLY
