from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Your Slack Bot Token
slack_token = "xoxb-6800278956247-DyqARQRA"
client = WebClient(token=slack_token)

try:
    # Upload the file
    response = client.files_upload(
        channels="C08PFVZV9PF",
        file="cost-report.txt",
        initial_comment="AWS Cost Report"
    )
    print("File uploaded successfully:", response)

except SlackApiError as e:
    print(f"Error uploading file: {e.response['error']}")
