import os
import base64
import email
from email.mime.text import MIMEText
import time
import logging
import re
import sys # For checking environment variables
import requests # For sending HTTP requests
from datetime import datetime, timezone # For timestamping
from dotenv import load_dotenv  # Import load_dotenv from dotenv
import sqlite3 ### --- ADDED --- ###: For SQLite database interaction

load_dotenv()
# Google API Libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# OpenAI Library
import openai

# --- Configuration ---
# !! IMPORTANT: Set the email address you are monitoring !!
MONITORED_EMAIL_ADDRESS = os.getenv("MONITORED_EMAIL", "admin@mausamrai.com.np") # Use env var if set

# Scopes required for reading, modifying, and sending emails
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/gmail.send']
CREDENTIALS_FILE = 'credentials.json' # Expect in the same directory
TOKEN_FILE = 'token.json'              # Will be created/used here
POLL_INTERVAL_SECONDS = 10 # Check for new emails every 30 seconds
OPENAI_MODEL = "gpt-4o-mini" # Or use "gpt-4", "gpt-4-turbo", etc.

# --- Dashboard Configuration ---
DASHBOARD_ENDPOINT = os.getenv("DASHBOARD_ENDPOINT", None) # Set to None or "" to disable
DASHBOARD_TIMEOUT_SECONDS = 10 # Timeout for the request to the dashboard

# --- ### ADDED: Database Configuration --- ###
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Construct path to DB in parent directory (../database.db)
#DATABASE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', 'database.db'))
DATABASE_PATH = os.getenv('DATABASE_PATH', '/app/database/database.db')
# You might not need this if the volume mount creates it, but it doesn't hurt.
DATABASE_DIR = os.path.dirname(DATABASE_PATH)
os.makedirs(DATABASE_DIR, exist_ok=True)

DB_TABLE_NAME = "phishing_log"

# --- Logging Setup ---
# Log to both file and console/stdout (useful for Docker logs)
LOG_FILE = 'email_monitor.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout) # Use stdout for Docker compatibility
    ]
)
logging.info("Script starting up.")
logging.info(f"Monitoring Email: {MONITORED_EMAIL_ADDRESS}")
if DASHBOARD_ENDPOINT:
    logging.info(f"Dashboard reporting enabled: Sending phishing alerts to {DASHBOARD_ENDPOINT}")
else:
    logging.info("Dashboard reporting disabled (DASHBOARD_ENDPOINT not set).")
logging.info(f"Database logging enabled: Storing phishing details in {DATABASE_PATH}") ### --- ADDED --- ###


# --- OpenAI Setup ---
openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    logging.error("FATAL: OpenAI API key not found in environment variable 'OPENAI_API_KEY'.")
    sys.exit("OpenAI API key missing.") # Exit if key is not set

try:
    # Use the recommended way to initialize the client
    client = openai.OpenAI(api_key=openai_api_key)
    # Test connection (optional but good practice)
    client.models.list()
    logging.info("OpenAI client initialized successfully.")
except openai.AuthenticationError:
     logging.error("FATAL: OpenAI Authentication Error. Check your API key.")
     sys.exit("OpenAI Authentication Failed.")
except Exception as e:
    logging.error(f"FATAL: Failed to initialize OpenAI client: {e}")
    sys.exit("OpenAI Initialization Failed.")


# --- Gmail Authentication ---
def get_gmail_service():
    """Authenticates with Gmail API and returns the service object."""
    creds = None
    script_dir = os.path.dirname(os.path.abspath(__file__)) # Redefined here, can use global SCRIPT_DIR
    token_path = os.path.join(script_dir, TOKEN_FILE)
    creds_path = os.path.join(script_dir, CREDENTIALS_FILE)
    logging.info(f"Looking for credentials in: {script_dir}")


    if not os.path.exists(creds_path):
        logging.error(f"FATAL: Credentials file not found at: {creds_path}")
        return None

    if os.path.exists(token_path):
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
            logging.info(f"Loaded credentials from {token_path}")
        except Exception as e:
             logging.warning(f"Failed to load token from {token_path}: {e}. Will attempt re-authentication.")
             creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logging.info("Refreshing expired credentials...")
            try:
                creds.refresh(Request())
                # Save the refreshed credentials
                with open(token_path, 'w') as token:
                    token.write(creds.to_json())
                logging.info(f"Refreshed and saved credentials to {token_path}")
            except Exception as e:
                logging.warning(f"Failed to refresh token: {e}. Removing old token and re-authenticating.")
                if os.path.exists(token_path): os.remove(token_path)
                creds = None
        # If creds is None or refresh failed, start the auth flow
        if not creds:
            try:
                logging.info("No valid credentials found or refresh failed. Starting authentication flow...")
                flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
                # Use run_console for environments without a browser, like Docker if needed initially
                # creds = flow.run_console()
                # For local runs / initial token generation:
                creds = flow.run_local_server(port=0)
                with open(token_path, 'w') as token:
                    token.write(creds.to_json())
                logging.info(f"Credentials obtained via auth flow and saved to {token_path}")
            except FileNotFoundError:
                 logging.error(f"FATAL: Credentials file not found at {creds_path}. Cannot authenticate.")
                 return None
            except Exception as e:
                 logging.error(f"FATAL: Error during authentication flow: {e}")
                 return None

    try:
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        actual_email = profile.get('emailAddress')
        logging.info(f"Successfully authenticated Gmail service for: {actual_email}")
        # Allow monitoring even if auth user differs, but log warning
        if actual_email.lower() != MONITORED_EMAIL_ADDRESS.lower():
            logging.warning(f"Auth user ({actual_email}) doesn't match monitored address ({MONITORED_EMAIL_ADDRESS}). Ensure correct account was used for auth, but proceeding.")
        return service
    except HttpError as error:
        logging.error(f'An error occurred during Gmail service build: {error}')
        if error.resp.status in [401, 403]:
             logging.error("Authentication/Authorization error for Gmail. Token might be invalid/revoked.")
             if os.path.exists(token_path):
                 try: os.remove(token_path); logging.info("Removed potentially invalid token file.")
                 except OSError as e: logging.error(f"Error removing token file: {e}")
        return None
    except Exception as e:
        logging.error(f'An unexpected error during Gmail service build: {e}')
        return None

# --- Email Parsing Logic ---
# (parse_email_parts function remains unchanged)
def parse_email_parts(parts):
    body_plain = ""
    body_html = ""
    if parts:
        for part in parts:
            mimeType = part.get('mimeType')
            part_body = part.get('body')
            data = part_body.get('data') if part_body else None

            if mimeType == 'text/plain' and data:
                try:
                    body_plain += base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                except Exception as decode_err:
                    logging.warning(f"Error decoding plain text part: {decode_err}")
            elif mimeType == 'text/html' and data:
                try:
                    body_html += base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                except Exception as decode_err:
                    logging.warning(f"Error decoding html text part: {decode_err}")
            elif part.get('parts'):
                # Recursively search nested parts
                nested_plain, nested_html = parse_email_parts(part.get('parts'))
                body_plain += nested_plain
                body_html += nested_html
    return body_plain, body_html

# (get_email_details function remains largely unchanged, ensures headers are extracted)
def get_email_details(service, msg_id):
    try:
        msg = service.users().messages().get(
            userId='me', id=msg_id, format='full' # Need 'full' for body content
        ).execute()

        payload = msg.get('payload', {})
        headers = payload.get('headers', [])

        details = {
            'id': msg_id,
            'snippet': msg.get('snippet'),
            'headers': {},
            'body_plain': '',
            'body_html': ''
        }

        # Extract common headers
        for h in headers:
            name = h.get('name', '').lower() # Ensure name exists
            if name in ['from', 'to', 'subject', 'date', 'message-id']: # Added message-id
                details['headers'][name] = h.get('value')

        # Extract body
        if 'parts' in payload:
            details['body_plain'], details['body_html'] = parse_email_parts(payload['parts'])
        else:
            # Handle single-part emails
            mimeType = payload.get('mimeType')
            body_data = payload.get('body', {}).get('data')
            if body_data:
                decoded_body = ""
                try:
                    decoded_body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                except Exception as decode_err:
                    logging.warning(f"Error decoding single part body for {msg_id}: {decode_err}")

                if mimeType == 'text/plain':
                    details['body_plain'] = decoded_body
                elif mimeType == 'text/html':
                    details['body_html'] = decoded_body

        # Prefer plain text, fallback to simple stripped HTML if plain is empty
        if not details['body_plain'] and details['body_html']:
             logging.debug(f"Plain text body empty for {msg_id}, using basic stripped HTML.")
             try:
                 # Basic strip - consider a more robust HTML parser if needed
                 cleaned_html = re.sub(r'<style.*?</style>', '', details['body_html'], flags=re.DOTALL | re.IGNORECASE)
                 cleaned_html = re.sub(r'<script.*?</script>', '', cleaned_html, flags=re.DOTALL | re.IGNORECASE)
                 cleaned_html = re.sub(r'<[^>]+>', ' ', cleaned_html) # Replace tags with space
                 cleaned_html = re.sub(r'\s+', ' ', cleaned_html).strip() # Collapse whitespace
                 details['body_plain'] = cleaned_html
             except Exception as html_parse_err:
                 logging.warning(f"Error stripping HTML for {msg_id}: {html_parse_err}. Body may be incomplete.")
                 details['body_plain'] = "Error parsing HTML Body" # Fallback content


        return details

    except HttpError as error:
        logging.error(f'An HTTP error occurred getting message {msg_id}: {error}')
        return None
    except Exception as e:
        logging.error(f'An unexpected error occurred getting message {msg_id}: {e}', exc_info=True) # Log traceback
        return None

# --- OpenAI Phishing Classification ---
# (classify_as_phishing function remains unchanged)
def classify_as_phishing(text_content, sender, subject):
    """Uses OpenAI to classify email content as phishing or not_phishing."""
    if not text_content or text_content.isspace():
         logging.warning("Email content is empty or whitespace, classifying as not_phishing.")
         return "not_phishing"

    try:
        # Limit content length to manage token usage/cost
        max_length = 4000 # Characters, adjust based on model and budget
        truncated_content = text_content[:max_length]
        if len(text_content) > max_length:
            logging.debug(f"Truncated email body from {len(text_content)} to {max_length} chars for classification.")


        prompt = f"""Analyze the following email content, considering the sender and subject.
Classify it strictly as 'phishing' if it appears to be a phishing attempt (e.g., suspicious links, urgent requests for credentials/money, impersonation, unusual sender/links, threats, grammatical errors typical of scams).
Otherwise, classify it strictly as 'not_phishing'.
Respond with ONLY the single word 'phishing' or 'not_phishing'.

Sender: {sender}
Subject: {subject}
--- Email Body ---
{truncated_content}
--- End Body ---

Classification:"""

        logging.debug("Sending classification request to OpenAI...")
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a highly accurate classification assistant. Respond with only 'phishing' or 'not_phishing'."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=5, # Only need one word
            temperature=0.0, # Make classification deterministic
            n=1,
            stop=None # Ensure it doesn't stop prematurely
        )
        classification = response.choices[0].message.content.strip().lower()
        logging.debug(f"Raw OpenAI response: '{classification}'")

        # Validate response
        if classification == "phishing":
            return "phishing"
        elif classification == "not_phishing":
            return "not_phishing"
        else:
            # Handle unexpected responses
            logging.warning(f"OpenAI returned unexpected classification: '{classification}'. Defaulting to 'not_phishing'.")
            return "not_phishing" # Safer to default to not phishing

    except openai.APIError as e:
        logging.error(f"OpenAI API returned an API Error: {e}")
    except openai.APIConnectionError as e:
        logging.error(f"Failed to connect to OpenAI API: {e}")
    except openai.RateLimitError as e:
        logging.error(f"OpenAI API request exceeded rate limit: {e}")
    except openai.AuthenticationError as e:
       logging.error(f"OpenAI Authentication Error during classification (check key again): {e}")
       # Potentially exit or disable OpenAI feature if key is invalid
    except Exception as e:
        logging.error(f"An unexpected error occurred during OpenAI classification: {e}")

    return "error" # Return 'error' if classification failed

# --- Gmail Actions ---
# (create_warning_email, send_email, mark_email_as_read functions remain unchanged)
def create_warning_email(recipient, original_sender, original_subject, message_id):
    """Creates the warning email message."""
    subject = f"[Automated Alert] Potentially Harmful Email Detected"
    body = f"""Hello,

Our automated system has flagged an email recently received in your inbox ({recipient}) as potentially malicious or phishing. Please exercise extreme caution.

Details of the flagged email:
  Original Sender: {original_sender}
  Original Subject: {original_subject}
  Internal ID: {message_id}

Recommendation:
  - Do NOT click on any links or download attachments from the original email.
  - Do NOT reply or provide any personal information.
  - If you recognize the sender but the content seems suspicious, verify with them through a separate, trusted communication channel (e.g., phone call).
  - Consider deleting the original email (or it may be moved to Spam/Trash by other filters).

This is an automated notification from your monitoring system.
"""
    message = MIMEText(body, 'plain', 'utf-8') # Ensure utf-8
    message['to'] = recipient
    message['from'] = recipient # Send from the monitored address itself
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_email(service, message_body):
    """Sends an email using the Gmail API."""
    try:
        message = service.users().messages().send(userId='me', body=message_body).execute()
        logging.info(f'Warning email sent successfully. Message Id: {message["id"]}')
        return True
    except HttpError as error:
        logging.error(f'An HTTP error occurred sending warning email: {error}')
        return False
    except Exception as e:
        logging.error(f'An unexpected error occurred sending warning email: {e}')
        return False

def mark_email_as_read(service, msg_id):
    """Removes the UNREAD label from an email."""
    try:
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        logging.info(f"Marked email {msg_id} as read.")
        return True
    except HttpError as error:
        logging.error(f'An HTTP error occurred marking email {msg_id} as read: {error}')
        return False
    except Exception as e:
        logging.error(f'An unexpected error occurred marking email {msg_id} as read: {e}')
        return False


# --- Dashboard Reporting Function ---
# (send_to_dashboard function remains unchanged)
def send_to_dashboard(phishing_data):
    """Sends phishing email details to the configured dashboard endpoint."""
    if not DASHBOARD_ENDPOINT:
        logging.debug("Dashboard endpoint not configured. Skipping report.")
        return False

    headers = {'Content-Type': 'application/json'}
    try:
        logging.info(f"Sending phishing report to dashboard: {DASHBOARD_ENDPOINT}")
        response = requests.post(
            DASHBOARD_ENDPOINT,
            json=phishing_data,
            headers=headers,
            timeout=DASHBOARD_TIMEOUT_SECONDS
        )
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        logging.info(f"Successfully sent report to dashboard. Status: {response.status_code}")
        return True
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Dashboard reporting failed: Connection error to {DASHBOARD_ENDPOINT} - {e}")
    except requests.exceptions.Timeout as e:
        logging.error(f"Dashboard reporting failed: Request timed out after {DASHBOARD_TIMEOUT_SECONDS}s - {e}")
    except requests.exceptions.HTTPError as e:
        logging.error(f"Dashboard reporting failed: HTTP error {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Dashboard reporting failed: An unexpected error occurred with requests library - {e}")
    except Exception as e:
        logging.error(f"Dashboard reporting failed: An unexpected error - {e}", exc_info=True)

    return False

def initialize_database():
    """Connects to the SQLite database and creates the table if it doesn't exist."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        # Create table with columns requested
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {DB_TABLE_NAME} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                monitored_email TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                body TEXT,
                gmail_internal_id TEXT UNIQUE NOT NULL
            )
        ''')
        conn.commit()
        logging.info(f"Database {DATABASE_PATH} initialized successfully. Table '{DB_TABLE_NAME}' ready.")
    except sqlite3.Error as e:
        logging.error(f"FATAL: Failed to initialize database at {DATABASE_PATH}: {e}")
        # Depending on severity, you might want to exit or disable DB logging
        # For now, just log the error and continue (logging will fail later)
    finally:
        if conn:
            conn.close()

def log_phishing_to_db(data):
    """Logs the details of a phishing email to the SQLite database."""
    conn = None # Ensure conn is defined for the finally block
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        sql = f''' INSERT INTO {DB_TABLE_NAME}
                    (timestamp, monitored_email, sender, subject, body, gmail_internal_id)
                    VALUES(?, ?, ?, ?, ?, ?) '''
        # Prepare data tuple matching the SQL parameters
        log_data = (
            data.get('detected_at', datetime.now(timezone.utc).isoformat()),
            data.get('source_email', 'N/A'),
            data.get('sender', 'N/A'),
            data.get('subject', 'N/A'),
            data.get('body', ''), # Store the plain text body
            data.get('gmail_internal_id', 'N/A')
        )
        cursor.execute(sql, log_data)
        conn.commit()
        logging.info(f"Successfully logged phishing email {data.get('gmail_internal_id')} to database.")
        return True
    except sqlite3.IntegrityError as e:
        # Handle cases where the gmail_internal_id might already exist (e.g., script restart/retry)
        logging.warning(f"Database logging failed for {data.get('gmail_internal_id')}: IntegrityError (likely duplicate entry) - {e}")
        return False # Indicate failure but don't crash
    except sqlite3.Error as e:
        logging.error(f"Database logging failed for {data.get('gmail_internal_id')}: {e}")
        return False
    except Exception as e:
         logging.error(f"Unexpected error during database logging for {data.get('gmail_internal_id')}: {e}", exc_info=True)
         return False
    finally:
        if conn:
            conn.close()
# --- ### End Added Database Functions --- ###


# --- Main Execution Loop ---
def main():
    # --- ### ADDED: Initialize DB --- ###
    initialize_database()

    gmail_service = get_gmail_service()
    if not gmail_service:
        logging.error("FATAL: Failed to initialize Gmail Service on startup. Exiting.")
        sys.exit("Gmail init failed.")

    logging.info(f"Starting email monitor main loop for {MONITORED_EMAIL_ADDRESS}.")

    while True:
        try:
            # Ensure service is valid before proceeding
            if not gmail_service:
                logging.warning("Gmail service is not available. Attempting re-authentication.")
                time.sleep(POLL_INTERVAL_SECONDS * 2) # Wait longer before retrying auth
                gmail_service = get_gmail_service()
                if not gmail_service:
                    logging.error("Re-authentication failed. Waiting before next main loop iteration.")
                    time.sleep(POLL_INTERVAL_SECONDS * 5) # Wait much longer
                    continue # Skip to next loop iteration
                else:
                    logging.info("Gmail service re-initialized successfully.")

            # 1. Check for unread emails
            logging.debug("Checking for unread emails...")
            results = gmail_service.users().messages().list(
                userId='me',
                # q='is:unread in:inbox', # Check inbox
                q=f'is:unread label:inbox -from:{MONITORED_EMAIL_ADDRESS}', # Check inbox, exclude self-sent
                maxResults=10 # Process up to 10 emails per cycle to avoid overwhelming APIs
            ).execute()
            messages = results.get('messages', [])

            if not messages:
                logging.debug(f"No new messages. Sleeping for {POLL_INTERVAL_SECONDS} seconds.")
            else:
                logging.info(f"Detected {len(messages)} new message(s). Processing...")
                for message_meta in messages:
                    msg_id = message_meta['id']
                    details = None # Ensure details is defined in this scope
                    classification_successful = False # Flag to track if processing steps before marking read were ok
                    body = "" # Initialize body in outer scope for DB logging
                    sender = "N/A"
                    subject = "N/A"
                    message_identifier = msg_id # Default identifier

                    try:
                        logging.info(f"--- Processing Email ID: {msg_id} ---")

                        # 2. Get Email Details
                        details = get_email_details(gmail_service, msg_id)
                        if not details:
                            logging.error(f"Could not retrieve details for message {msg_id}. Skipping.")
                            # Don't mark as read if details failed
                            continue # Process next message

                        sender = details['headers'].get('from', 'N/A')
                        subject = details['headers'].get('subject', 'N/A')
                        message_identifier = details['headers'].get('message-id', msg_id) # Use Message-ID header if available
                        body = details['body_plain'] # Use plain text for classification

                        logging.info(f"   From: {sender}")
                        logging.info(f"   Subject: {subject}")
                        logging.info(f"   Identifier: {message_identifier}")


                        # 3. Classify with OpenAI
                        classification = classify_as_phishing(body, sender, subject)
                        logging.info(f"   Classification result: {classification}")

                        if classification == "error":
                             logging.error(f"   Classification failed for {msg_id}. Email will remain unread for retry.")
                             classification_successful = False
                             # Optional: Add a delay here before processing next message if API errors frequently
                             # time.sleep(10)
                        else:
                             classification_successful = True # Classification itself succeeded (even if not phishing)

                             # 4. Log, Send Warning, Report to Dashboard, Log to DB if Phishing
                             if classification == "phishing":
                                 logging.warning(f"   ACTION: Email {msg_id} classified as PHISHING.")

                                 # Send warning email to the monitored address
                                 warning_email_body = create_warning_email(
                                     MONITORED_EMAIL_ADDRESS, # Send warning to self
                                     sender,
                                     subject,
                                     message_identifier # Pass identifier
                                 )
                                 send_success = send_email(gmail_service, warning_email_body)
                                 if not send_success:
                                     logging.error(f"   Failed to send warning email for {msg_id}.")
                                     # Decide if this failure should prevent marking as read. Usually not.

                                 # Prepare data common for dashboard and DB
                                 phishing_event_data = {
                                     "source_email": MONITORED_EMAIL_ADDRESS,
                                     "sender": sender,
                                     "subject": subject,
                                     "message_id": message_identifier, # Use header or internal ID
                                     "gmail_internal_id": msg_id,
                                     "detected_at": datetime.now(timezone.utc).isoformat(), # Use UTC time in ISO format
                                     "body": body # ### ADDED body for DB logging ###
                                 }

                                 # --- Send data to dashboard (if enabled) ---
                                 if DASHBOARD_ENDPOINT:
                                     send_to_dashboard(phishing_event_data) # Pass the prepared data

                                 # --- ### ADDED: Log to Database --- ###
                                 log_phishing_to_db(phishing_event_data) # Pass the same data
                                 # Note: Failure to log to DB currently doesn't stop marking as read.

                             else: # Not phishing
                                 logging.info(f"   Email {msg_id} classified as not phishing.")

                    except Exception as proc_err:
                        # Catch unexpected errors during single message processing
                        logging.error(f"Unexpected error processing message {msg_id}: {proc_err}", exc_info=True)
                        classification_successful = False # Treat as failed for safety

                    finally:
                        # 5. Mark as Read ONLY if processed successfully (details fetched AND classification didn't error)
                        if details and classification_successful:
                            mark_email_as_read(gmail_service, msg_id)
                        else:
                             logging.warning(f"   Email {msg_id} not marked as read due to processing/classification error or detail retrieval failure.")

                    # Optional small delay between processing messages in a batch
                    time.sleep(2) # Be kind to APIs

        except HttpError as error:
            logging.error(f'An error occurred in main loop (Gmail API): {error}')
            if error.resp.status in [401, 403]:
                 logging.error("Authentication/Authorization error during operation. Invalidating service object.")
                 # Invalidate service object to trigger re-auth attempt in the next loop
                 gmail_service = None
                 time.sleep(POLL_INTERVAL_SECONDS * 2) # Wait longer after auth error
            elif error.resp.status == 429 or error.resp.status >= 500:
                 logging.warning(f"Gmail API rate limit or server error ({error.resp.status}). Sleeping longer.")
                 time.sleep(POLL_INTERVAL_SECONDS * 5)
            else:
                 time.sleep(POLL_INTERVAL_SECONDS) # Wait default time for other errors

        except Exception as e:
            logging.error(f'An unexpected critical error occurred in the main loop: {e}', exc_info=True)
            # Consider more drastic recovery or exit strategy for critical errors
            logging.info("Attempting to recover by pausing significantly...")
            time.sleep(POLL_INTERVAL_SECONDS * 3)
            # Invalidate service to try re-auth
            gmail_service = None


        # Wait before the next check cycle
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == '__main__':
    main()