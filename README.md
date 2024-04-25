# SlackOTP

This Flask application integrates with Slack to manage Time-based One-Time Passwords (TOTP). It provides a way for users to generate TOTPs for shared accounts directly through Slack commands within a specified channel.

## Configuration

### Environment Variables

The application uses several environment variables for configuration:

- `SLACK_SIGNING_SECRET`: The signing secret provided by Slack to verify incoming requests.
- `SLACK_TEAM_ID`: Your Slack workspace ID to ensure that requests come from your Slack workspace.
- `SLACK_BOT_TOKEN`: The bot user OAuth access token used by the Slack API to perform actions.
- `SLACK_ALLOWED_CHANNEL_ID`: (Optional) The ID of the Slack channel allowed to interact with the bot. If not set, the bot will respond to commands from any channel.
- `TOTP_SECRETS`: JSON formatted string containing the TOTP secrets for various services.

### Setting Up the `TOTP_SECRETS`

The `TOTP_SECRETS` environment variable should contain a JSON string with key-value pairs where each key is a service name and each value is the corresponding TOTP secret. Here's how to set it:

#### Format Example

```json
{
    "service1": "base32secret1",
    "service2": "base32secret2",
    "service3": "base32secret3"
}