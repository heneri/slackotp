import sys
from flask import Flask, request, jsonify, abort
from flask_talisman import Talisman
import json
import pyotp
import os
import hmac
import hashlib
import base64
import time
import datetime
import logging
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,  # Set the logging level
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# flask
app = Flask(__name__)

# talisman
csp = {
    'default-src': '\'self\''
}
talisman = Talisman(app, content_security_policy=csp)

# Initialize global variable for secrets
secrets = {}

def check_environment_vars():
    required_vars = ['SLACK_SIGNING_SECRET', 'SLACK_TEAM_ID', 'SLACK_BOT_TOKEN']
    missing_or_empty_vars = [var for var in required_vars if not os.getenv(var, "").strip()]

    if missing_or_empty_vars:
        logging.error("Missing or empty necessary environment variables: %s", ', '.join(missing_or_empty_vars))
        sys.exit(1)


check_environment_vars()

# Environment variables for security and configuration
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET').encode()
SLACK_TEAM_ID = os.getenv('SLACK_TEAM_ID')
SLACK_ALLOWED_CHANNEL_ID = os.getenv('SLACK_ALLOWED_CHANNEL_ID')
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')

# Load OTP secrets from an environment variable
def load_secrets():
    secrets_json = os.getenv('TOTP_SECRETS')
    if secrets_json:
        try:
            return json.loads(secrets_json)
        except json.JSONDecodeError as e:
            logging.error("Decoding JSON has failed: %s", e)
            return {}
    else:
        logging.error("No secrets configured in the environment.")
        return {}


# Slack client initialization with the bot token
client = WebClient(token=SLACK_BOT_TOKEN)

# Call load_secrets at startup
secrets = load_secrets()

# Generate a OTP code using pyotp
def generate_totp(secret):
    try:
        totp = pyotp.TOTP(secret)
        ttl = int(totp.interval - (datetime.datetime.now().timestamp() % totp.interval))
        return totp.now(), ttl
    except (TypeError, base64.binascii.Error):
        logging.error("Invalid Base32 secret.")
        return None, None


# Verify Slack request signature to ensure requests come from Slack
def verify_slack_request():
    request_body = request.get_data(as_text=True)
    timestamp = request.headers.get('X-Slack-Request-Timestamp')

    # Log the user making the request
    logging.info(f"OTP request made by {request.form['user_name']}({request.form['user_id']})")

    if not timestamp or abs(time.time() - int(timestamp)) > 60 * 5:
        logging.warning("Timestamp is missing or too far from current time.")
        return False  # Missing or too old timestamp

    sig_basestring = f'v0:{timestamp}:{request_body}'.encode('utf-8')
    my_signature = 'v0=' + hmac.new(SLACK_SIGNING_SECRET, sig_basestring, hashlib.sha256).hexdigest()
    slack_signature = request.headers.get('X-Slack-Signature')

    if not slack_signature:
        logging.warning("Slack signature is missing from the headers.")
        return False

    if not hmac.compare_digest(my_signature, slack_signature):
        logging.warning("Failed to verify Slack signature.")
        return False

    return True


# Verify that the request is from the correct Slack team
def verify_slack_team_id():
    team_id = request.form.get('team_id')
    if team_id != SLACK_TEAM_ID:
        logging.warning(f"Incorrect team ID: {team_id}")
        return False
    return True


# If the allowed channel ID is set, verify against it
def verify_channel_id():
    channel_id = request.form.get('channel_id')

    if SLACK_ALLOWED_CHANNEL_ID and channel_id != SLACK_ALLOWED_CHANNEL_ID:
        logging.warning(f"Unauthorized channel access attempted: {channel_id}")
        return False
    return True


def send_private_response(channel, user_id, message):
    blocks = [{
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": message
        }
    }]
    try:
        client.chat_postEphemeral(channel=channel, user=user_id, text=message, blocks=blocks)
        logging.info("Private message sent successfully")
        return ('', 200)
    except SlackApiError as e:
        logging.error(f"Failed to send private message: {str(e)}")
        return jsonify({'error': 'Failed to send private message'}), 500


def announce_in_channel(channel, message):
    blocks = [{
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": message
        }
    }]
    try:
        client.chat_postMessage(channel=channel, text=message, blocks=blocks)
        logging.info("Public announcement sent successfully")
        return ('', 200)
    except SlackApiError as e:
        logging.error(f"Failed to send public announcement: {str(e)}")
        return jsonify({'error': 'Failed to send public announcement'}), 500


@app.route('/slack/command', methods=['POST'])
def slack_commands():
    if not verify_slack_request() or not verify_slack_team_id() or not verify_channel_id():
        abort(403)  # Forbidden if verification fails

    command_text = request.form.get('text', '').strip().lower()
    user_id = request.form['user_id']  # Retrieve user ID from the request
    channel_id = request.form['channel_id']
    user_name = request.form['user_name']  # Assuming the user's name is passed in the form

    if command_text == 'list':
        services_list = "\n".join(secrets.keys())  # Generate line-separated list of services
        # Send only an ephemeral message for listing services
        return send_private_response(channel_id, user_id, f"*Available services:*\n{services_list}")
    elif command_text in secrets:
        secret = secrets[command_text]
        otp,ttl = generate_totp(secret)
        send_private_response(channel_id, user_id, f"*Service*: {command_text} *TTL*: {ttl}s  *OTP*: {otp}")
        # Announce in the channel that an OTP was requested
        return announce_in_channel(channel_id, f"{user_name} requested an OTP for the service: *{command_text}*")
    else:
        # Send ephemeral message for invalid command
        return send_private_response(channel_id, user_id, "Invalid command or service. Use 'list' to see available services.")


@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)