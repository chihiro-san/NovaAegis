import os
import time
import base64
import email
from email.mime.text import MIMEText
import logging # Recommended for background scripts

# Google API Libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# OpenAI Library
import openai

# --- Configuration ---
# Scopes required for reading and sending emails
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.send',
          'https://www.googleapis.com/auth/gmail.modify'] # Modify to mark as read
CREDENTIALS_FILE = 'credentials.json' # Path to your credentials file
TOKEN_FILE = 'token.json'
POLL_INTERVAL_SECONDS = 60 # Check for new emails every 60 seconds
YOUR_EMAIL_ADDRESS = "your_email@gmail.com" # The address being monitored AND receiving warnings

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- OpenAI Setup ---
try:
    openai.api_key = os.getenv("OPENAI_API_KEY")
    if not openai.api_key:
        raise ValueError("OpenAI API key not found in environment variables.")
    # Initialize the OpenAI client (Update based on current openai library version if needed)
    client = openai.OpenAI()
except Exception as e:
    logging.error(f"Failed to initialize OpenAI: {e}")
    exit(1) # Exit if OpenAI setup fails

# --- Gmail Authentication ---
def get_gmail_service():
    """Authenticates with Gmail API and returns the service object."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                logging.warning(f"Failed to refresh token: {e}. Re-authenticating.")
                # If refresh fails, force re-authentication
                if os.path.exists(TOKEN_FILE):
                    os.remove(TOKEN_FILE)
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
            logging.info(f"Credentials saved to {TOKEN_FILE}")

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


# --- OpenAI Classification ---
def classify_email_content(text_content):
    """Uses OpenAI to classify email content as harmful or not."""
    if not text_content or text_content.isspace():
         logging.warning("Email content is empty or whitespace, classifying as not_harmful.")
         return "not_harmful"

    try:
        # Limit content length to avoid excessive token usage
        max_length = 3500 # Adjust as needed, consider token limits
        truncated_content = text_content[:max_length]

        prompt = f"""Analyze the following email content and classify it strictly as either 'harmful' or 'not_harmful'.
        'Harmful' includes scams, phishing attempts, malicious links/attachments mentioned, abusive language, threats, or highly suspicious requests.
        Otherwise, classify as 'not_harmful'.

        Email Content:
        ---
        {truncated_content}
        ---

        Classification:"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo", # Or use a more advanced model like gpt-4
            messages=[
                {"role": "system", "content": "You are a classification assistant. Respond with only 'harmful' or 'not_harmful'."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=10,
            temperature=0.0 # Make classification deterministic
        )
        classification = response.choices[0].message.content.strip().lower()
        logging.info(f"OpenAI classification result: {classification}")

        if "harmful" in classification:
            return "harmful"
        else:
            return "not_harmful"

    except openai.APIError as e:
        logging.error(f"OpenAI API returned an API Error: {e}")
    except openai.APIConnectionError as e:
        logging.error(f"Failed to connect to OpenAI API: {e}")
    except openai.RateLimitError as e:
        logging.error(f"OpenAI API request exceeded rate limit: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during OpenAI classification: {e}")

    return "error" # Return 'error' if classification failed


# --- Email Processing ---
def get_email_body(payload):
    """Extracts plain text body from email payload."""
    body = ""
    if 'parts' in payload:
        for part in payload['parts']:
            # Prioritize plain text
            if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
                return body # Return first plain text part found
            # Recurse for multipart/* parts
            elif part['mimeType'].startswith('multipart/'):
                recursive_body = get_email_body(part)
                if recursive_body: # If found text in nested part
                    return recursive_body
            # Fallback to HTML if plain text not found yet (basic extraction)
            elif body == "" and part['mimeType'] == 'text/html' and 'data' in part['body']:
                 # Very basic HTML stripping - consider a library like BeautifulSoup for better results
                 html_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
                 # Simple placeholder, replace with actual stripping if needed
                 import re
                 body = re.sub('<[^<]+?>', '', html_content) # Crude tag removal

    elif 'body' in payload and 'data' in payload['body'] and payload.get('mimeType') == 'text/plain':
         body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='replace')

    # Add check for HTML body directly under payload['body'] if no parts or plain text found
    elif 'body' in payload and 'data' in payload['body'] and body == "" and payload.get('mimeType') == 'text/html':
        html_content = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='replace')
        import re
        body = re.sub('<[^<]+?>', '', html_content) # Crude tag removal


    return body

def create_warning_email(original_sender, original_subject):
    """Creates the warning email message."""
    message = MIMEText(f"""Caution: An email you recently received has been flagged as potentially harmful by our automated system.

Original Sender: {original_sender}
Original Subject: {original_subject}

Please exercise extreme caution when interacting with the original email. Do not click links, download attachments, or provide personal information unless you are absolutely certain of the sender's legitimacy.
""")
    message['to'] = YOUR_EMAIL_ADDRESS # Send warning to yourself
    message['from'] = YOUR_EMAIL_ADDRESS # Send from your own address
    message['subject'] = f"[Automated Warning] Potentially Harmful Email Received (From: {original_sender})"
    # Encode the message for the Gmail API
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_email(service, message_body):
    """Sends an email using the Gmail API."""
    try:
        message = service.users().messages().send(userId='me', body=message_body).execute()
        logging.info(f'Warning email sent. Message Id: {message["id"]}')
        return message
    except HttpError as error:
        logging.error(f'An error occurred sending email: {error}')
        return None
    except Exception as e:
        logging.error(f'An unexpected error occurred sending email: {e}')
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
    except HttpError as error:
        logging.error(f'An error occurred marking email {msg_id} as read: {error}')
    except Exception as e:
        logging.error(f'An unexpected error occurred marking email {msg_id} as read: {e}')


# --- Main Loop ---
def main():
    gmail_service = get_gmail_service()
    if not gmail_service:
        logging.error("Failed to get Gmail service. Exiting.")
        return

    logging.info("Starting email monitoring loop...")
    while True:
        try:
            # 1. Check for unread emails
            results = gmail_service.users().messages().list(
                userId='me',
                q='is:unread in:inbox' # Query for unread messages in the inbox
            ).execute()
            messages = results.get('messages', [])

            if not messages:
                logging.debug(f"No new messages found. Sleeping for {POLL_INTERVAL_SECONDS} seconds.")
            else:
                logging.info(f"Found {len(messages)} new message(s).")
                for message_meta in messages:
                    msg_id = message_meta['id']
                    try:
                        # 2. Fetch full email details
                        msg = gmail_service.users().messages().get(
                            userId='me', id=msg_id, format='full' # Use 'full' or 'metadata'
                        ).execute()

                        payload = msg.get('payload', {})
                        headers = payload.get('headers', [])

                        # Extract Subject and Sender
                        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')

                        logging.info(f"Processing email ID: {msg_id}, From: {sender}, Subject: {subject}")

                        # 3. Extract email body
                        email_content = get_email_body(payload)
                        if not email_content:
                             logging.warning(f"Could not extract text body from email {msg_id}. Skipping classification.")
                             # Optionally mark as read even if body extraction fails
                             mark_email_as_read(gmail_service, msg_id)
                             continue # Skip to next message

                        # 4. Classify content
                        classification = classify_email_content(email_content)

                        # 5. Act based on classification
                        if classification == "harmful":
                            logging.warning(f"Email {msg_id} classified as HARMFUL.")
                            # 6. Send warning email
                            warning_email_body = create_warning_email(sender, subject)
                            send_email(gmail_service, warning_email_body)
                            # 7. Mark original email as read
                            mark_email_as_read(gmail_service, msg_id)

                        elif classification == "not_harmful":
                            logging.info(f"Email {msg_id} classified as not harmful.")
                            # 7. Mark original email as read
                            mark_email_as_read(gmail_service, msg_id)
                        else: # Handle classification error
                             logging.error(f"Classification failed for email {msg_id}. It will remain unread for now.")
                             # Don't mark as read if classification failed, so it can be retried

                    except HttpError as error:
                        logging.error(f'An error occurred processing message {msg_id}: {error}')
                        # Decide if you want to skip the message or retry later
                    except Exception as e:
                         logging.error(f'An unexpected error occurred processing message {msg_id}: {e}')
                         # Decide if you want to skip or retry

        except HttpError as error:
            logging.error(f'An error occurred listing messages: {error}')
            # Handle potential API errors during listing (e.g., rate limits)
            if error.resp.status == 401:
                 logging.error("Authentication error. Token might be invalid. Attempting to remove token file.")
                 if os.path.exists(TOKEN_FILE):
                     os.remove(TOKEN_FILE)
                 gmail_service = get_gmail_service() # Try to re-authenticate
                 if not gmail_service:
                     logging.error("Re-authentication failed. Exiting.")
                     break # Exit the loop if re-auth fails
            elif error.resp.status == 429 or error.resp.status >= 500:
                 logging.warning(f"Rate limit or server error ({error.resp.status}). Sleeping longer.")
                 time.sleep(POLL_INTERVAL_SECONDS * 5) # Back off significantly

        except Exception as e:
            logging.error(f'An unexpected error occurred in the main loop: {e}')
            # Consider adding a longer sleep or exit strategy for persistent errors

        # Wait before checking again
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == '__main__':
    main()