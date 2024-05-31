# Snowflake Security Tool by Titan

Monitor and manage Snowflake users and sessions in real-time

## Features

- **Session Management**: List, watch in real-time, and kill user sessions based on various criteria such as user-specific, all sessions, or suspicious sessions.
- **User Management**: List users, disable user accounts, and reset user credentials. It supports filtering users based on suspicious or inactive criteria.
- **Security Features**: Identify suspicious sessions based on predefined IP blocklists and client environment settings.

## Installation

To set up this tool, follow these steps:

1. Ensure that Python 3.8 or higher is installed on your system.
2. Clone this repository to your local machine.
3. Install the required Python packages:

```
git clone https://github.com/Titan-Systems/titan-security-tools.git
cd titan-security-tools
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp EXAMPLE.env .env
```

4. Set up a `.env` file in the root directory with the necessary Snowflake credentials:

```
SNOWFLAKE_ACCOUNT=your_account
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_ROLE=your_role
SNOWFLAKE_WAREHOUSE=your_warehouse
```

## Usage

The tool is executed through a command-line interface. Here are some of the common commands:

### Sessions

```bash
# Realtime view of Snowflake sessions
python main.py sessions watch

# List all active sessions
python main.py sessions list

# Get a CSV of all sessions
python main.py sessions list --format=csv

# Kill a specific session
python main.py sessions kill --id 123

# Kill all sessions
python main.py sessions kill --all

# Kill all sessions for a specific user
python main.py sessions kill --user some_user_name

# Kill all suspicious sessions
python main.py sessions kill --suspicious
```

### Users

```bash
# List all users
python main.py users list

# List all suspicious users
python main.py users list --suspicious

# Disable a user
python main.py users disable --user username

# Reset credentials for a user
python main.py users reset --user username

# Reset credentials for all suspicious users
python main.py users reset --suspicious

# Reset credentials for inactive users
python main.py users reset --inactive
```
