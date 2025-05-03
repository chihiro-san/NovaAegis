import os
import base64
import email
import time
import logging
import re

# Google API Libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
# Scopes required for reading and modifying emails (to mark as read)
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify']
CREDENTIALS_FILE = 'credentials.json' # Should be in the same directory as the script
TOKEN_FILE = 'token.json'             # Will be created/used in the same directory
# Specify the email address being monitored
MONITORED_EMAIL_ADDRESS = "admin@mausamrai.com.np"
POLL_INTERVAL_SECONDS = 60 # Check for new emails every 60 seconds

# --- Logging Setup ---
# For background scripts, logging to a file is essential
LOG_FILE = 'email_monitor.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE), # Log to a file
        logging.StreamHandler()        # Also log to console (useful for testing)
    ]
)

# --- Gmail Authentication ---
def get_gmail_service():
    """Authenticates with Gmail API and returns the service object."""
    creds = None
    script_dir = os.path.dirname(os.path.abspath(__file__))
    token_path = os.path.join(script_dir, TOKEN_FILE)
    creds_path = os.path.join(script_dir, CREDENTIALS_FILE)

    if not os.path.exists(creds_path):
        logging.error(f"Credentials file not found at: {creds_path}")
        logging.error("Please download credentials.json from Google Cloud Console and place it in the script's directory.")
        return None

    if os.path.exists(token_path):
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        except Exception as e:
             logging.warning(f"Failed to load token from {token_path}: {e}. Will attempt re-authentication.")
             creds = None # Ensure creds is None if loading failed

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logging.info("Refreshing expired credentials...")
            try:
                creds.refresh(Request())
            except Exception as e:
                logging.warning(f"Failed to refresh token: {e}. Removing old token and re-authenticating.")
                if os.path.exists(token_path):
                    try:
                        os.remove(token_path)
                    except OSError as E:
                         logging.error(f"Error removing token file {token_path}: {E}")
                creds = None # Force re-auth
        # If creds is None or refresh failed, start the auth flow
        if not creds:
            try:
                logging.info("No valid credentials found or refresh failed. Starting authentication flow...")
                flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
                # Use run_local_server for Desktop app credentials
                creds = flow.run_local_server(port=0) # Opens browser for user auth
            except FileNotFoundError:
                 logging.error(f"Credentials file not found at {creds_path}. Cannot authenticate.")
                 return None
            except Exception as e:
                 logging.error(f"Error during authentication flow: {e}")
                 return None

        # Save the credentials for the next run
        try:
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
            logging.info(f"Credentials saved to {token_path}")
        except Exception as e:
             logging.error(f"Failed to save token to {token_path}: {e}")

    try:
        service = build('gmail', 'v1', credentials=creds)
        # Verify the service is working for the correct user
        profile = service.users().getProfile(userId='me').execute()
        actual_email = profile.get('emailAddress')
        logging.info(f"Successfully authenticated Gmail service for: {actual_email}")
        if actual_email.lower() != MONITORED_EMAIL_ADDRESS.lower():
            logging.warning(f"Warning: Authenticated user ({actual_email}) does not match MONITORED_EMAIL_ADDRESS ({MONITORED_EMAIL_ADDRESS}). Ensure the correct account was used during authentication.")
        return service
    except HttpError as error:
        logging.error(f'An error occurred during Gmail service build: {error}')
        # Specific check for auth errors that might require re-auth
        if error.resp.status == 401 or error.resp.status == 403:
             logging.error("Authentication/Authorization error. The token might be invalid or revoked.")
             if os.path.exists(token_path):
                 try:
                     os.remove(token_path)
                     logging.info("Removed potentially invalid token file. Please restart the script to re-authenticate.")
                 except OSError as e:
                      logging.error(f"Error removing token file: {e}")
        return None
    except Exception as e:
        logging.error(f'An unexpected error occurred during Gmail service build: {e}')
        return None

# --- Email Processing ---

def parse_email_parts(parts):
    """Recursively parses email parts to find text/plain and text/html bodies."""
    body_plain = ""
    body_html = ""
    if parts:
        for part in parts:
            mimeType = part.get('mimeType')
            part_body = part.get('body')
            data = part_body.get('data') if part_body else None

            if mimeType == 'text/plain' and data:
                body_plain += base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
            elif mimeType == 'text/html' and data:
                body_html += base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
            elif part.get('parts'):
                # Recursively search nested parts
                nested_plain, nested_html = parse_email_parts(part.get('parts'))
                body_plain += nested_plain
                body_html += nested_html
    return body_plain, body_html


def get_email_details(service, msg_id):
    """Fetches and extracts key headers and body from an email."""
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
            name = h.get('name').lower()
            if name in ['from', 'to', 'subject', 'date']:
                details['headers'][name] = h.get('value')

        # Extract body
        if 'parts' in payload:
            details['body_plain'], details['body_html'] = parse_email_parts(payload['parts'])
        else:
            # Handle single-part emails
            mimeType = payload.get('mimeType')
            body_data = payload.get('body', {}).get('data')
            if body_data:
                decoded_body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
                if mimeType == 'text/plain':
                    details['body_plain'] = decoded_body
                elif mimeType == 'text/html':
                    details['body_html'] = decoded_body

        # Prefer plain text, fallback to HTML if plain is empty
        if not details['body_plain'] and details['body_html']:
             # Basic HTML strip (replace with BeautifulSoup for better results if needed)
             logging.debug(f"Plain text body empty for {msg_id}, using basic stripped HTML.")
             details['body_plain'] = re.sub('<[^<]+?>', '', details['body_html'])


        return details

    except HttpError as error:
        logging.error(f'An HTTP error occurred getting message {msg_id}: {error}')
        return None
    except Exception as e:
        logging.error(f'An unexpected error occurred getting message {msg_id}: {e}')
        return None

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

# --- Main Loop ---
def main():
    gmail_service = get_gmail_service()
    if not gmail_service:
        logging.error("Failed to get Gmail service. Exiting.")
        return # Exit if authentication fails

    logging.info(f"Starting email monitor for {MONITORED_EMAIL_ADDRESS}. Checking every {POLL_INTERVAL_SECONDS} seconds.")
    logging.info(f"Logging output to: {os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILE)}")

    while True:
        try:
            # 1. Check for unread emails
            results = gmail_service.users().messages().list(
                userId='me',
                q='is:unread in:inbox' # Standard query for new mail
            ).execute()
            messages = results.get('messages', [])

            if not messages:
                logging.debug(f"No new messages found. Sleeping...") # Debug level for less noise
            else:
                logging.info(f"Detected {len(messages)} new message(s).")
                for message_meta in messages:
                    msg_id = message_meta['id']
                    logging.info(f"--- Processing New Email (ID: {msg_id}) ---")

                    # 2. Get Email Details (Body & Headers)
                    details = get_email_details(gmail_service, msg_id)

                    if details:
                        logging.info(f"  From: {details['headers'].get('from', 'N/A')}")
                        logging.info(f"  To: {details['headers'].get('to', 'N/A')}")
                        logging.info(f"  Subject: {details['headers'].get('subject', 'N/A')}")
                        logging.info(f"  Date: {details['headers'].get('date', 'N/A')}")
                        # Log body snippet for brevity, you have the full body in 'details' if needed
                        body_preview = (details['body_plain'][:200] + '...' ) if len(details['body_plain']) > 200 else details['body_plain']
                        logging.info(f"  Body (Preview):\n{body_preview}\n--------------------")

                        # HERE: You would add your OpenAI classification call using details['body_plain'] or details['headers']

                        # 3. Mark as Read (to avoid re-processing)
                        mark_email_as_read(gmail_service, msg_id)
                    else:
                         logging.error(f"Could not retrieve details for message {msg_id}. It will remain unread.")

        except HttpError as error:
            logging.error(f'An error occurred interacting with Gmail API: {error}')
            # Handle specific errors if needed (e.g., rate limits, auth errors)
            if error.resp.status == 401 or error.resp.status == 403:
                 logging.error("Authentication/Authorization error during operation. Attempting to handle...")
                 # Attempt to force re-auth on next loop by trying to get service again
                 # Consider removing token file here if errors persist
                 if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), TOKEN_FILE)):
                     logging.warning("Attempting to remove token file due to auth error.")
                     try:
                         os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), TOKEN_FILE))
                     except OSError as e:
                         logging.error(f"Could not remove token file: {e}")
                 gmail_service = None # Force re-auth attempt next loop
                 time.sleep(POLL_INTERVAL_SECONDS * 2) # Wait longer after auth error
                 continue # Skip rest of the loop
            elif error.resp.status == 429 or error.resp.status >= 500:
                 logging.warning(f"Rate limit or server error ({error.resp.status}). Sleeping longer.")
                 time.sleep(POLL_INTERVAL_SECONDS * 5) # Back off significantly
            else:
                # Other HTTP errors, wait and retry
                 time.sleep(POLL_INTERVAL_SECONDS)

        except Exception as e:
            logging.error(f'An unexpected error occurred in the main loop: {e}', exc_info=True) # Log traceback
            # Basic recovery: wait and hope it's temporary
            time.sleep(POLL_INTERVAL_SECONDS * 2)

        # Re-authenticate if service became None due to error handling
        if not gmail_service:
             logging.info("Attempting to re-initialize Gmail service...")
             gmail_service = get_gmail_service()
             if not gmail_service:
                 logging.error("Re-initialization failed. Waiting before retry.")
                 time.sleep(POLL_INTERVAL_SECONDS * 3) # Wait even longer if re-auth fails

        # Wait before the next check
        logging.debug(f"Sleeping for {POLL_INTERVAL_SECONDS} seconds...")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == '__main__':
    main()