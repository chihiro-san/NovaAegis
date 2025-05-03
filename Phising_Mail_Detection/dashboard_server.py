import logging
from flask import Flask, request, jsonify

# --- Configuration ---
LISTEN_HOST = '0.0.0.0' # Listen on all network interfaces (use 'localhost' or '127.0.0.1' to only listen locally)
LISTEN_PORT = 5000      # The port number specified in your DASHBOARD_ENDPOINT
ENDPOINT_PATH = '/get_phising_data' # The path specified in your DASHBOARD_ENDPOINT

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Flask App Initialization ---
app = Flask(__name__)
logging.info(f"Flask app initialized. Ready to listen on {LISTEN_HOST}:{LISTEN_PORT}")

# --- Define the Endpoint ---
@app.route(ENDPOINT_PATH, methods=['POST']) # Listen on the specified path, accept only POST requests
def receive_phishing_data():
    """
    This function handles incoming POST requests to the ENDPOINT_PATH.
    It expects JSON data in the request body.
    """
    logging.info(f"Received request on {ENDPOINT_PATH}")

    # 1. Check if the incoming request contains JSON data
    if not request.is_json:
        logging.warning("Request received is not in JSON format.")
        # Return a 400 Bad Request error
        return jsonify({"status": "error", "message": "Request must be JSON"}), 400

    # 2. Get the JSON data from the request
    try:
        data = request.get_json()
        logging.info(f"Received data: {data}")

        # --- >>> YOUR DASHBOARD LOGIC GOES HERE <<< ---
        # 3. Process the received data
        # Access specific fields like:
        source_email = data.get('source_email')
        sender = data.get('sender')
        subject = data.get('subject')
        message_id = data.get('message_id')
        detected_at = data.get('detected_at')
        # (Add more fields as needed from the 'data' dictionary)

        if not all([source_email, sender, subject, message_id, detected_at]):
             logging.warning("Received JSON is missing expected fields.")
             # You might still accept it or return an error depending on your needs
             # return jsonify({"status": "error", "message": "Missing required fields in JSON"}), 400


        # Example Actions:
        # - Store the data in a database
        # - Add the data to an in-memory list/queue for the dashboard to display
        # - Send a notification via WebSocket to connected dashboard clients
        # - Write to a log file specific to phishing reports
        print("-----------------------------------------")
        print(f"** Phishing Alert Received **")
        print(f"  Monitored Account: {source_email}")
        print(f"  Original Sender: {sender}")
        print(f"  Original Subject: {subject}")
        print(f"  Message ID: {message_id}")
        print(f"  Detected At (UTC): {detected_at}")
        print("-----------------------------------------")
        # --- >>> END OF YOUR DASHBOARD LOGIC AREA <<< ---

        # 4. Send a success response back to the monitoring script
        response_data = {"status": "success", "message": "Phishing data received successfully"}
        return jsonify(response_data), 200 # 200 OK status

    except Exception as e:
        logging.error(f"Error processing request: {e}", exc_info=True)
        # Return a 500 Internal Server Error
        return jsonify({"status": "error", "message": "Internal server error processing data"}), 500

# --- Run the Flask Development Server ---
if __name__ == '__main__':
    logging.info(f"Starting Flask server on {LISTEN_HOST}:{LISTEN_PORT}...")
    # Set debug=False for production environments
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=True)