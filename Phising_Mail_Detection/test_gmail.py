import os
import base64
import logging
from email.mime.text import MIMEText

# Google API Libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
# Make sure all necessary scopes are included
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',  # To list and read emails
          'https://www.googleapis.com/auth/gmail.send',    # To send emails
          'https://www.googleapis.com/auth/gmail.modify']  # To mark emails as read/unread etc.
CREDENTIALS_FILE = 'credentials.json' # Path to your credentials file
TOKEN_FILE = 'token.json'
# !!! --- IMPORTANT: Set this to your Gmail address --- !!!
YOUR_EMAIL_ADDRESS = "admin@mausamrai.com.np" # Used as sender and recipient for test email

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Gmail Authentication ---
def get_gmail_service():
    """Authenticates with Gmail API and returns the service object."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
             logging.warning(f"Failed to load token from {TOKEN_FILE}: {e}. Will attempt re-authentication.")
             creds = None # Ensure creds is None if loading failed

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logging.info("Refreshing expired credentials...")
            try:
                creds.refresh(Request())
            except Exception as e:
                logging.warning(f"Failed to refresh token: {e}. Re-authenticating.")
                # If refresh fails, force re-authentication by removing old token
                if os.path.exists(TOKEN_FILE):
                    try:
                        os.remove(TOKEN_FILE)
                        logging.info(f"Removed invalid token file: {TOKEN_FILE}")
                    except OSError as E:
                         logging.error(f"Error removing token file {TOKEN_FILE}: {E}")

                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
        else:
            logging.info("No valid credentials found or refresh failed. Starting authentication flow...")
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0) # Opens browser for user auth

        # Save the credentials for the next run
        try:
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
            logging.info(f"Credentials saved to {TOKEN_FILE}")
        except Exception as e:
             logging.error(f"Failed to save token to {TOKEN_FILE}: {e}")


    try:
        service = build('gmail', 'v1', credentials=creds)
        logging.info("Gmail service authenticated successfully.")
        return service
    except HttpError as error:
        logging.error(f'An error occurred during Gmail service build: {error}')
        return None
    except Exception as e:
        logging.error(f'An unexpected error occurred during Gmail service build: {e}')
        return None


# --- Test Functions ---

def test_list_unread(service):
    """Lists up to 10 unread messages."""
    logging.info("--- Testing: Listing Unread Messages ---")
    try:
        results = service.users().messages().list(
            userId='me',
            q='is:unread in:inbox', # Query for unread messages in inbox
            maxResults=10
        ).execute()
        messages = results.get('messages', [])

        if not messages:
            logging.info("No unread messages found in the inbox.")
            return None # Return None if no messages found
        else:
            logging.info(f"Found {len(messages)} unread message(s) (showing up to 10).")
            for i, message in enumerate(messages):
                logging.info(f"  Unread Message ID [{i+1}]: {message['id']}")
            return messages[0]['id'] # Return the ID of the *first* unread message for further testing

    except HttpError as error:
        logging.error(f'An HTTP error occurred while listing messages: {error}')
        return None
    except Exception as e:
         logging.error(f'An unexpected error occurred while listing messages: {e}')
         return None


def test_send_email(service, recipient):
    """Sends a simple test email."""
    logging.info("--- Testing: Sending Email ---")
    if not recipient or '@' not in recipient:
         logging.error("Invalid or missing recipient email address in YOUR_EMAIL_ADDRESS.")
         return False
    try:
        message_text = "This is an automated test email sent by the Python Gmail API test script."
        message = MIMEText(message_text)
        message['to'] = recipient
        message['from'] = recipient # Sending from your own address
        message['subject'] = "Gmail API Test Script - Send Function"

        # Encode the message for the API
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': raw_message}

        sent_message = service.users().messages().send(userId='me', body=create_message).execute()
        logging.info(f"Test email sent successfully. Message ID: {sent_message['id']}")
        return True

    except HttpError as error:
        logging.error(f'An HTTP error occurred sending email: {error}')
        return False
    except Exception as e:
        logging.error(f'An unexpected error occurred sending email: {e}')
        return False


def test_get_and_modify(service, message_id):
    """Gets details of a specific message and marks it as read."""
    logging.info(f"--- Testing: Get & Modify Message (ID: {message_id}) ---")
    if not message_id:
        logging.warning("No message ID provided to get/modify. Skipping.")
        return False

    try:
        # 1. Get message metadata (less data than 'full')
        logging.info(f"Attempting to fetch metadata for message ID: {message_id}...")
        msg = service.users().messages().get(
            userId='me', id=message_id, format='metadata' # Fetch only headers/metadata
        ).execute()

        headers = msg.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'N/A')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'N/A')
        logging.info(f"  Subject: {subject}")
        logging.info(f"  From: {sender}")
        logging.info(f"  Labels: {msg.get('labelIds', [])}")

        # 2. Modify the message: Remove the UNREAD label
        logging.info(f"Attempting to mark message ID: {message_id} as READ...")
        modify_body = {'removeLabelIds': ['UNREAD']}
        updated_msg = service.users().messages().modify(
            userId='me', id=message_id, body=modify_body
        ).execute()

        logging.info(f"Successfully marked message as read. New Labels: {updated_msg.get('labelIds', [])}")
        return True

    except HttpError as error:
        logging.error(f'An HTTP error occurred getting/modifying message {message_id}: {error}')
        return False
    except Exception as e:
        logging.error(f'An unexpected error occurred getting/modifying message {message_id}: {e}')
        return False

# --- Main Execution ---
if __name__ == '__main__':
    logging.info("Starting Gmail API Test Script...")

    if YOUR_EMAIL_ADDRESS == "your_email@gmail.com":
         logging.error("Please update the 'YOUR_EMAIL_ADDRESS' variable in the script before running.")
         exit()

    gmail_service = get_gmail_service()

    if gmail_service:
        logging.info("Gmail Service Initialized.")

        # Test 1: List unread messages
        first_unread_id = test_list_unread(gmail_service)
        print("-" * 30) # Separator

        # Test 2: Send a test email
        test_send_email(gmail_service, YOUR_EMAIL_ADDRESS)
        print("-" * 30) # Separator

        # Test 3: Get details of the first unread message and mark it as read
        # Only run if an unread message was found in Test 1
        if first_unread_id:
            test_get_and_modify(gmail_service, first_unread_id)
        else:
            logging.info("Skipping Get/Modify test as no unread messages were found initially.")
        print("-" * 30) # Separator

        logging.info("Gmail API testing finished.")

    else:
        logging.error("Failed to initialize Gmail Service. Cannot run tests.")