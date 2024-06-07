# =============================================================================
# Copyright (C) 2024 Titan Systems, Inc
#
# This script is open source and available under the MIT License.
# You may use, distribute, and modify this code under the terms of the MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =============================================================================

import csv
import io
import json
import os
import secrets
import string
import shutil
import time

from datetime import timedelta

import click
import snowflake.connector

from tabulate import tabulate

IP_BLOCKLIST = [
    "104.223.91.28",
    "198.54.135.99",
    "184.147.100.29",
    "146.70.117.210",
    "198.54.130.153",
    "169.150.203.22",
    "185.156.46.163",
    "146.70.171.99",
    "206.217.206.108",
    "45.86.221.146",
    "193.32.126.233",
    "87.249.134.11",
    "66.115.189.247",
    "104.129.24.124",
    "146.70.171.112",
    "198.54.135.67",
    "146.70.124.216",
    "45.134.142.200",
    "206.217.205.49",
    "146.70.117.56",
    "169.150.201.25",
    "66.63.167.147",
    "194.230.144.126",
    "146.70.165.227",
    "154.47.30.137",
    "154.47.30.150",
    "96.44.191.140",
    "146.70.166.176",
    "198.44.136.56",
    "176.123.6.193",
    "192.252.212.60",
    "173.44.63.112",
    "37.19.210.34",
    "37.19.210.21",
    "185.213.155.241",
    "198.44.136.82",
    "93.115.0.49",
    "204.152.216.105",
    "198.44.129.82",
    "185.248.85.59",
    "198.54.131.152",
    "102.165.16.161",
    "185.156.46.144",
    "45.134.140.144",
    "198.54.135.35",
    "176.123.3.132",
    "185.248.85.14",
    "169.150.223.208",
    "162.33.177.32",
    "194.230.145.67",
    "5.47.87.202",
    "194.230.160.5",
    "194.230.147.127",
    "176.220.186.152",
    "194.230.160.237",
    "194.230.158.178",
    "194.230.145.76",
    "45.155.91.99",
    "194.230.158.107",
    "194.230.148.99",
    "194.230.144.50",
    "185.204.1.178",
    "79.127.217.44",
    "104.129.24.115",
    "146.70.119.24",
    "138.199.34.144",
    "198.44.136.35",
    "66.115.189.210",
    "206.217.206.88",
    "37.19.210.28",
    "146.70.225.67",
    "138.199.43.92",
    "149.102.246.3",
    "43.225.189.163",
    "185.201.188.34",
    "178.249.209.163",
    "199.116.118.210",
    "198.54.130.147",
    "156.59.50.195",
    "198.44.136.195",
    "198.44.129.67",
    "37.19.221.170",
    "96.44.189.99",
    "146.70.134.3",
    "66.115.189.200",
    "103.75.11.51",
    "69.4.234.118",
    "146.70.173.195",
    "138.199.60.29",
    "66.115.189.160",
    "154.47.30.144",
    "178.249.211.80",
    "143.244.47.92",
    "146.70.132.227",
    "193.19.207.226",
    "46.19.136.227",
    "68.235.44.35",
    "103.136.147.4",
    "198.54.133.163",
    "169.150.203.16",
    "146.70.224.3",
    "87.249.134.15",
    "198.54.134.131",
    "142.147.89.226",
    "146.70.117.35",
    "193.19.207.196",
    "146.70.144.35",
    "146.70.173.131",
    "107.150.22.3",
    "169.150.201.29",
    "146.70.117.163",
    "146.70.138.195",
    "146.70.184.67",
    "104.129.57.67",
    "185.248.85.49",
    "146.70.168.67",
    "138.199.43.66",
    "79.127.217.35",
    "194.127.167.108",
    "194.36.25.49",
    "146.70.171.67",
    "138.199.60.3",
    "45.134.212.93",
    "146.70.187.67",
    "66.63.167.163",
    "154.47.29.3",
    "149.102.246.16",
    "198.44.129.99",
    "146.70.128.195",
    "185.65.134.191",
    "146.70.119.35",
    "87.249.134.28",
    "149.102.240.67",
    "103.75.11.67",
    "69.4.234.124",
    "169.150.196.3",
    "169.150.201.3",
    "185.188.61.196",
    "87.249.134.2",
    "138.199.15.163",
    "45.134.213.195",
    "138.199.6.208",
    "169.150.227.223",
    "146.70.200.3",
    "149.88.22.156",
    "173.205.85.35",
    "206.217.206.48",
    "194.36.25.4",
    "154.47.16.48",
    "37.19.200.131",
    "146.70.166.131",
    "37.19.221.144",
    "149.88.20.207",
    "79.127.222.195",
    "194.127.167.88",
    "96.44.191.131",
    "69.4.234.119",
    "138.199.6.221",
    "146.70.128.227",
    "66.63.167.195",
    "169.150.196.16",
    "185.201.188.4",
    "173.44.63.67",
    "79.127.222.208",
    "198.54.134.99",
    "198.54.135.131",
    "138.199.43.79",
    "66.115.189.190",
    "149.88.20.194",
    "141.98.252.190",
    "129.227.46.163",
    "31.171.154.51",
    "79.127.217.48",
    "69.4.234.116",
    "206.217.206.68",
    "103.125.233.19",
    "146.70.188.131",
    "169.150.227.198",
    "129.227.46.131",
    "198.44.136.99",
    "149.88.22.130",
    "193.138.7.138",
    "146.70.168.195",
    "169.150.203.29",
    "206.217.205.118",
    "146.70.185.3",
    "146.70.124.131",
    "194.127.199.32",
    "149.102.240.80",
    "143.244.47.79",
    "178.255.149.166",
    "188.241.176.195",
    "69.4.234.125",
    "138.199.21.240",
    "45.134.79.98",
    "178.249.209.176",
    "68.235.44.3",
    "198.54.133.131",
    "193.138.7.158",
    "154.47.30.131",
    "204.152.216.115",
    "206.217.205.125",
    "37.19.200.144",
    "146.70.171.131",
    "198.54.130.99",
    "149.22.81.208",
    "146.70.197.131",
    "198.54.131.131",
    "138.199.15.147",
    "185.248.85.34",
    "143.244.47.66",
    "92.60.40.225",
    "178.249.214.3",
    "146.70.133.3",
    "179.43.189.67",
    "69.4.234.120",
    "146.70.199.195",
    "185.156.46.157",
    "45.134.142.194",
    "68.235.44.195",
    "209.54.101.131",
    "104.129.41.195",
    "146.70.225.3",
    "206.217.205.126",
    "103.136.147.130",
    "194.110.115.3",
    "178.249.211.93",
    "185.188.61.226",
    "194.110.115.35",
    "146.70.198.195",
    "169.150.198.67",
    "103.108.229.67",
    "138.199.60.16",
    "96.44.191.147",
    "31.170.22.16",
    "45.134.140.131",
    "169.150.196.29",
    "103.216.220.19",
    "173.205.93.3",
    "146.70.199.131",
    "103.214.20.131",
    "149.88.22.143",
    "149.40.50.113",
    "138.199.21.227",
    "138.199.6.195",
    "103.216.220.35",
    "198.44.136.67",
    "199.116.118.194",
    "146.70.129.131",
    "199.116.118.233",
    "146.70.184.3",
    "185.254.75.14",
    "38.240.225.69",
    "149.22.81.195",
    "43.225.189.132",
    "45.134.142.207",
    "146.70.196.195",
    "198.44.140.195",
    "206.217.205.119",
    "38.240.225.37",
    "169.150.227.211",
    "37.19.200.157",
    "146.70.132.195",
    "146.70.211.67",
    "206.217.206.28",
    "178.249.214.16",
    "149.88.22.169",
    "149.88.104.16",
    "194.36.25.34",
    "146.70.197.195",
    "45.134.212.80",
    "156.59.50.227",
    "104.223.91.19",
    "198.54.130.131",
    "185.248.85.19",
    "45.134.79.68",
    "45.134.142.220",
    "185.204.1.179",
    "146.70.129.99",
    "146.70.133.99",
    "69.4.234.122",
    "178.249.211.67",
    "198.54.131.163",
    "198.44.129.35",
    "103.108.231.51",
    "146.70.165.3",
    "37.19.221.157",
    "92.60.40.210",
    "154.47.16.35",
    "194.127.199.3",
    "37.19.210.2",
    "103.108.231.67",
    "204.152.216.99",
    "176.123.7.143",
    "176.123.10.35",
    "195.160.223.23",
]

CLIENT_ENVIRONMENT_BLOCKLIST = [
    {"APPLICATION": "rapeflake"},
    {"APPLICATION": "DBeaver_DBeaverUltimate", "OS": "Windows Server 2022"},
]


def connect():
    if os.path.exists(".env"):
        from dotenv import load_dotenv

        load_dotenv()
    return snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        password=os.environ["SNOWFLAKE_PASSWORD"],
        role=os.environ.get("SNOWFLAKE_ROLE"),
        warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE"),
    )


def execute(sql):
    with connect() as conn:
        with conn.cursor(snowflake.connector.DictCursor) as cur:
            return cur.execute(sql).fetchall()


def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")


def trunc(s, max_length=16):
    return s if len(s) <= max_length else s[:max_length] + "..."


def generate_password():
    alphabet = string.ascii_letters + string.digits + "-_!@#$%^&*()"
    password = "".join(secrets.choice(alphabet) for i in range(60)) + "aA1@"
    return password


def time_ago(timestamp):
    timestamp /= 1000
    current_time = time.time()
    difference = current_time - timestamp
    time_diff = timedelta(seconds=difference)
    periods = [
        ("year", 365 * 24 * 60 * 60),
        ("month", 30 * 24 * 60 * 60),
        ("day", 24 * 60 * 60),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    ]
    for period_name, period_seconds in periods:
        if time_diff.total_seconds() >= period_seconds:
            period_value, remainder = divmod(time_diff.total_seconds(), period_seconds)
            period_value = int(period_value)
            return f"{period_value} {period_name}{'s' if period_value > 1 else ''} ago"

    return "just now"


def session_client_environment_matches_blocklist(client_environment):
    environment = json.loads(client_environment)
    for rule in CLIENT_ENVIRONMENT_BLOCKLIST:
        if all(environment.get(k) == v for k, v in rule.items()):
            return True
    return False


def session_is_suspicious(session):
    if session["clientNetAddress"] in IP_BLOCKLIST:
        return True
    if session_client_environment_matches_blocklist(session["clientEnvironment"]):
        return True
    return False


def get_sessions() -> list[dict]:
    conn = connect()
    url = "/monitoring/sessions"
    response = conn.rest.request(
        url=url,
        method="get",
        client="rest",
    )
    if not response["success"]:
        raise Exception(response)
    conn.close()
    return response["data"]["sessions"]


def get_suspicious_users(users, sessions):
    suspicious_users = [
        session["userName"] for session in sessions if session_is_suspicious(session)
    ]
    suspicious_users = list(set(suspicious_users))
    return [user for user in users if user["name"] in suspicious_users]


def get_inactive_users(users, inactive_days=90):
    def is_inactive(user):
        return (
            user["last_success_login"] < time.time() - inactive_days * 24 * 60 * 60
            or user["last_success_login"] is None
        )

    return [user for user in users if is_inactive(user)]


def get_users() -> list[dict]:
    return execute("show users")


def print_users(users, display_limit=None):
    if display_limit is None:
        terminal_lines = shutil.get_terminal_size((80, 20)).lines
        display_limit = terminal_lines - 5

    selected_columns = [
        "name",
        "email",
        "disabled",
        "last_success_login",
        "has_password",
        "has_rsa_public_key",
    ]
    users = [[user[col] for col in selected_columns] for user in users]
    print(tabulate(users, headers=selected_columns))


def disable_user_account(user):
    execute(f"ALTER USER {user['name']} SET DISABLED = TRUE")


def reset_user_credentials(user):
    print(f"Resetting credentials for {user['name']}")
    execute(f"ALTER USER {user['name']} ABORT ALL QUERIES")
    print(" » Aborted all queries")
    authorizations = ["NUMERACY", "SNOWSCOPE", "APPLICA", "CLEANROOM"]
    for auth in authorizations:
        execute(
            f"SELECT SYSTEM$REMOVE_ALL_DELEGATED_AUTHORIZATIONS('{user['name']}', '{auth}')"
        )
        print(f" » Revoked delegated authorization {auth}")
    for secint in execute("SHOW SECURITY INTEGRATIONS"):
        execute(
            f"SELECT SYSTEM$REMOVE_ALL_DELEGATED_AUTHORIZATIONS('{user['name']}', '{secint['name']}')"
        )
        print(f" » Revoked security authorization {secint['name']}")
    execute(f"ALTER USER {user['name']} SET PASSWORD = '{generate_password()}'")
    print(" » Reset password")
    execute(f"ALTER USER {user['name']} UNSET RSA_PUBLIC_KEY")
    print(" » Reset RSA public key")
    execute(f"ALTER USER {user['name']} UNSET RSA_PUBLIC_KEY_2")
    print(" » Reset RSA public key 2")


def watch_sessions(user=None, refresh_rate=0.5):
    while True:
        sessions = get_sessions()
        if user:
            sessions = [s for s in sessions if s["userName"] == user]
        clear_terminal()
        print_sessions(sessions)
        time.sleep(refresh_rate)


def print_sessions(sessions, display_limit=None):
    if display_limit is None:
        terminal_lines = shutil.get_terminal_size((80, 20)).lines
        display_limit = terminal_lines - 5
    selected_columns = [
        "userName",
        "id",
        # "idAsString",
        "isActive",
        "startTime",
        # "endTime",
        "clientEnvironment",
        "clientApplication",
        "clientNetAddress",
        # "accountName",
        "authnMethod",
        # "defaultNamespace",
        # "lastQueryShort",
        # "lastQueryId",
        # "clientBuildId",
    ]

    column_renderers = {
        "startTime": time_ago,
        "endTime": time_ago,
        "clientEnvironment": lambda x: (
            f"*** {json.loads(x).get('APPLICATION', '')}"
            if session_client_environment_matches_blocklist(x)
            else json.loads(x).get("APPLICATION", "")
        ),
        "clientNetAddress": lambda x: f"*** {x}" if x in IP_BLOCKLIST else x,
    }

    header = selected_columns
    sessions = [
        [column_renderers.get(col, lambda x: x)(row[col]) for col in selected_columns]
        for row in sessions
    ]
    if len(sessions) > display_limit:
        total = len(sessions)
        sessions = sessions[:display_limit]
        sessions.append(["..."] * len(header))
        sessions.append(
            [f"And {total - display_limit} more"] + [""] * (len(header) - 1)
        )
    print(tabulate(sessions, headers=header))


def dump_sessions(sessions, format):
    if format != "csv":
        raise Exception("Only CSV format is supported")
    if not sessions:
        print("No data to print.")
        return
    headers = sessions[0].keys()
    with io.StringIO() as output:
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        writer.writerows(sessions)
        print(output.getvalue())


def kill_session_by_id(id: int):
    res = execute(f"SELECT SYSTEM$ABORT_SESSION({id})")[0]
    return res is not None


def kill_sessions_interactive(sessions: list[dict]):
    to_kill = sessions
    actioned = []

    terminal_lines = shutil.get_terminal_size((80, 20)).lines
    display_limit = terminal_lines - 5

    def session_record(session):
        return [session["userName"], session["id"], session["clientNetAddress"]]

    def render():
        clear_terminal()
        data = actioned + [[*session_record(s), "Active"] for s in to_kill]
        if len(data) > display_limit:
            data_size = len(data)
            data = data[:display_limit]
            data.append(["..."] * 3)
            data.append([f"And {data_size - display_limit} more"] + [""] * 3)
        print(tabulate(data, headers=["User", "ID", "IP", "Status"]))

    with connect() as conn:
        with conn.cursor() as cur:
            while to_kill:
                render()
                time.sleep(0.05)
                session = to_kill.pop(0)
                res = cur.execute(
                    f"SELECT SYSTEM$ABORT_SESSION({session['id']})"
                ).fetchone()[0]
                if res is not None:
                    actioned.append([*session_record(session), "Killed"])
                else:
                    actioned.append([*session_record(session), "Failed"])
    render()


# ----------------------
# CLI
# ----------------------


@click.group()
def cli():
    """Main CLI group"""
    pass


@cli.group()
def sessions():
    """Manage sessions"""
    pass


@sessions.command(name="list")
@click.option(
    "--format",
    type=click.Choice(["csv", "table"], case_sensitive=False),
    default="table",
    help="Output format: csv or table",
)
@click.option(
    "--limit", default=25, type=int, help="Limit the number of sessions to list"
)
def list_sessions(format, limit):
    """List all sessions"""
    sessions = get_sessions()
    if format == "csv":
        dump_sessions(sessions, format)
    else:
        print_sessions(sessions, display_limit=limit)


@sessions.command()
@click.option("--user", type=str, help="Username to filter sessions by")
def watch(user):
    """Watch sessions in real-time"""
    watch_sessions(user)


@sessions.command()
@click.option("--all", is_flag=True, help="Kill all sessions")
@click.option("--id", type=int, help="ID of the session to kill")
@click.option("--user", type=str, help="Username of the sessions to kill")
@click.option("--suspicious", is_flag=True, help="Kill all suspicious sessions")
def kill(all, id, user, suspicious):
    """Kill a specific session by ID or all sessions"""
    if all:
        sessions = get_sessions()
        kill_sessions_interactive(sessions)
    elif id is not None:
        if kill_session_by_id(id):
            print(f"Killed session {id}")
        else:
            print(f"Failed to kill session {id}")
    elif user is not None:
        sessions = get_sessions()
        sessions = [
            session
            for session in sessions
            if session["userName"].lower() == user.lower()
        ]
        kill_sessions_interactive(sessions)
    elif suspicious:
        sessions = get_sessions()

        sessions = [session for session in sessions if session_is_suspicious(session)]
        kill_sessions_interactive(sessions)
    else:
        click.echo(
            "Please provide either --all to kill all sessions or --id=<id> to kill a specific session."
        )


@cli.group()
def users():
    """Manage users"""
    pass


@users.command(name="list")
@click.option("--suspicious", is_flag=True, help="List only suspicious users")
def list_users(suspicious):
    """List all users"""
    users = get_users()
    if suspicious:
        sessions = get_sessions()
        users = get_suspicious_users(users, sessions)
    print_users(users)


@users.command(name="disable")
@click.option("--user", type=str, help="Username of the user to disable")
@click.option("--suspicious", is_flag=True, help="Disable all suspicious users")
@click.option("--inactive", is_flag=True, help="Disable all inactive users")
def disable_user(user, suspicious, inactive):
    """Disable user accounts based on the given criteria"""
    users = get_users()
    if user:
        users = [u for u in users if u["name"].lower() == user.lower()]
        for u in users:
            disable_user_account(u)
            print(f"Disabled user {u['name']}")
    elif suspicious:
        sessions = get_sessions()
        suspicious_users = get_suspicious_users(users, sessions)
        for u in suspicious_users:
            disable_user_account(u)
            print(f"Disabled suspicious user {u['name']}")
    elif inactive:
        inactive_users = get_inactive_users(users)
        for u in inactive_users:
            disable_user_account(u)
            print(f"Disabled inactive user {u['name']}")
    else:
        click.echo("Please specify a user, --suspicious, or --inactive option.")


@users.command()
@click.option("--user", type=str, help="Username of the user to disable")
@click.option("--suspicious", is_flag=True, help="Disable all suspicious users")
@click.option("--inactive", is_flag=True, help="Disable all inactive users")
def reset(user, suspicious, inactive):
    users = get_users()
    if user:
        users = [u for u in users if u["name"].lower() == user.lower()]
        for u in users:
            reset_user_credentials(u)
            print(f"Reset user {u['name']}")
    elif suspicious:
        sessions = get_sessions()
        suspicious_users = get_suspicious_users(users, sessions)
        for u in suspicious_users:
            reset_user_credentials(u)
            print(f"Reset suspicious user {u['name']}")
    elif inactive:
        inactive_users = get_inactive_users(users)
        for u in inactive_users:
            reset_user_credentials(u)
            print(f"Reset inactive user {u['name']}")


if __name__ == "__main__":
    cli()
