import os
import asyncio
import aiohttp
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from quart import Quart, redirect, request, jsonify, render_template_string
from discord.ext import commands
import discord

BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN")
CLIENT_ID = os.environ.get("CLIENT_ID", "YOUR_CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "YOUR_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "https://yourapp.onrender.com/callback")
API_KEY = os.environ.get("API_KEY", "your_secret_api_key_here")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

OAUTH_URL = f"https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify%20guilds.join"
SELF_URL = os.environ.get("SELF_URL", "https://yourapp.onrender.com")

app = Quart(__name__)
bot = commands.Bot(command_prefix="!", intents=discord.Intents.default())

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()[:16]

def verify_api_key(key):
    if not key or not API_KEY:
        return False
    return secrets.compare_digest(key, API_KEY)

def init_db():
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS members (
            user_id TEXT PRIMARY KEY,
            username TEXT,
            access_token TEXT,
            refresh_token TEXT,
            expires_at TEXT,
            verified_at TEXT,
            guild_id TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_member(user_id, username, access_token, refresh_token, expires_in, guild_id):
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
    c.execute("""
        INSERT OR REPLACE INTO members (user_id, username, access_token, refresh_token, expires_at, verified_at, guild_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, access_token, refresh_token, expires_at, datetime.utcnow().isoformat(), guild_id))
    conn.commit()
    conn.close()

def get_all_members():
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    c.execute("SELECT user_id, username, access_token, refresh_token, expires_at, verified_at, guild_id FROM members")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "user_id": r[0],
            "username": r[1],
            "access_token": r[2],
            "refresh_token": r[3],
            "expires_at": r[4],
            "verified_at": r[5],
            "guild_id": r[6]
        }
        for r in rows
    ]

async def exchange_code(code):
    async with aiohttp.ClientSession() as session:
        async with session.post("https://discord.com/api/oauth2/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI
        }) as resp:
            return await resp.json()

async def refresh_access_token(refresh_token):
    async with aiohttp.ClientSession() as session:
        async with session.post("https://discord.com/api/oauth2/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }) as resp:
            return await resp.json()

async def get_user_info(access_token):
    async with aiohttp.ClientSession() as session:
        async with session.get("https://discord.com/api/users/@me", headers={
            "Authorization": f"Bearer {access_token}"
        }) as resp:
            return await resp.json()

async def add_to_guild(guild_id, user_id, access_token):
    async with aiohttp.ClientSession() as session:
        async with session.put(
            f"https://discord.com/api/guilds/{guild_id}/members/{user_id}",
            headers={
                "Authorization": f"Bot {BOT_TOKEN}",
                "Content-Type": "application/json"
            },
            json={"access_token": access_token}
        ) as resp:
            return resp.status

VERIFY_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Verify</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
</head>
<body class="bg-[#0e0e10] min-h-screen flex items-center justify-center">
    <div class="bg-[#1e1f22] p-8 rounded-2xl text-center max-w-md">
        <h1 class="text-3xl font-bold text-white mb-4">Server Verification</h1>
        <p class="text-gray-400 mb-6">Click below to verify and gain access to the server</p>
        <a href="{{ oauth_url }}" class="inline-block bg-[#5865F2] hover:bg-[#4752C4] text-white font-semibold py-3 px-8 rounded-xl transition">
            Verify with Discord
        </a>
    </div>
</body>
</html>
"""

SUCCESS_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Verified!</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
</head>
<body class="bg-[#0e0e10] min-h-screen flex items-center justify-center">
    <div class="bg-[#1e1f22] p-8 rounded-2xl text-center max-w-md">
        <div class="text-6xl mb-4">✅</div>
        <h1 class="text-3xl font-bold text-white mb-4">Verified!</h1>
        <p class="text-gray-400">Welcome <span class="text-[#5865F2] font-semibold">{{ username }}</span>! You can close this tab now.</p>
    </div>
</body>
</html>
"""

@app.route("/verify/<guild_id>")
async def verify(guild_id):
    oauth_with_state = f"{OAUTH_URL}&state={guild_id}"
    return await render_template_string(VERIFY_PAGE, oauth_url=oauth_with_state)

@app.route("/callback")
async def callback():
    code = request.args.get("code")
    guild_id = request.args.get("state")
    
    if not code:
        return "no code provided", 400
    
    token_data = await exchange_code(code)
    
    if "access_token" not in token_data:
        return "failed to get token", 400
    
    access_token = token_data["access_token"]
    refresh_token = token_data["refresh_token"]
    expires_in = token_data["expires_in"]
    
    user_info = await get_user_info(access_token)
    user_id = user_info["id"]
    username = user_info["username"]
    
    save_member(user_id, username, access_token, refresh_token, expires_in, guild_id)
    
    if guild_id:
        await add_to_guild(guild_id, user_id, access_token)
    
    return await render_template_string(SUCCESS_PAGE, username=username)

@app.route("/health")
async def health():
    return jsonify({"status": "alive", "timestamp": datetime.utcnow().isoformat()})

@app.route("/api/members")
async def api_members():
    key = request.headers.get("X-API-Key")
    if not verify_api_key(key):
        await asyncio.sleep(1)
        return jsonify({"error": "unauthorized"}), 401
    
    members = get_all_members()
    return jsonify(members)

@app.route("/api/members/refresh/<user_id>", methods=["POST"])
async def api_refresh_member(user_id):
    key = request.headers.get("X-API-Key")
    if not verify_api_key(key):
        await asyncio.sleep(1)
        return jsonify({"error": "unauthorized"}), 401
    
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    c.execute("SELECT refresh_token FROM members WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "member not found"}), 404
    
    token_data = await refresh_access_token(row[0])
    
    if "access_token" not in token_data:
        return jsonify({"error": "refresh failed, user needs to reverify"}), 400
    
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    expires_at = (datetime.utcnow() + timedelta(seconds=token_data["expires_in"])).isoformat()
    c.execute("UPDATE members SET access_token = ?, refresh_token = ?, expires_at = ? WHERE user_id = ?",
              (token_data["access_token"], token_data["refresh_token"], expires_at, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "access_token": token_data["access_token"]})

@app.route("/api/pull/<guild_id>/<user_id>", methods=["POST"])
async def api_pull_member(guild_id, user_id):
    key = request.headers.get("X-API-Key")
    if not verify_api_key(key):
        await asyncio.sleep(1)
        return jsonify({"error": "unauthorized"}), 401
    
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    c.execute("SELECT access_token, expires_at, refresh_token FROM members WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "member not found"}), 404
    
    access_token = row[0]
    expires_at = datetime.fromisoformat(row[1])
    
    if datetime.utcnow() > expires_at:
        token_data = await refresh_access_token(row[2])
        if "access_token" not in token_data:
            return jsonify({"error": "token expired and refresh failed"}), 400
        access_token = token_data["access_token"]
        
        conn = sqlite3.connect("members.db")
        c = conn.cursor()
        new_expires = (datetime.utcnow() + timedelta(seconds=token_data["expires_in"])).isoformat()
        c.execute("UPDATE members SET access_token = ?, refresh_token = ?, expires_at = ? WHERE user_id = ?",
                  (access_token, token_data["refresh_token"], new_expires, user_id))
        conn.commit()
        conn.close()
    
    status = await add_to_guild(guild_id, user_id, access_token)
    
    return jsonify({"status": status, "success": status in [201, 204]})

@bot.event
async def on_ready():
    print(f"Bot is ready: {bot.user}")

@bot.command()
@commands.has_permissions(administrator=True)
async def setup(ctx):
    embed = discord.Embed(
        title="Verification Required",
        description="Click the button below to verify and access this server!",
        color=0x5865F2
    )
    
    view = discord.ui.View(timeout=None)
    button = discord.ui.Button(
        label="Verify",
        style=discord.ButtonStyle.link,
        url=f"http://localhost:5000/verify/{ctx.guild.id}"
    )
    view.add_item(button)
    
    await ctx.send(embed=embed, view=view)

@bot.command()
@commands.has_permissions(administrator=True)
async def stats(ctx):
    conn = sqlite3.connect("members.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM members WHERE guild_id = ?", (str(ctx.guild.id),))
    count = c.fetchone()[0]
    conn.close()
    
    await ctx.reply(f"**{count}** verified members in database for this server")

async def keep_alive():
    await asyncio.sleep(30)
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(f"{SELF_URL}/health") as resp:
                    print(f"[Keep-Alive] Pinged self: {resp.status}")
            except Exception as e:
                print(f"[Keep-Alive] Failed: {e}")
            await asyncio.sleep(720)

async def run_bot():
    await bot.start(BOT_TOKEN)

async def run_web():
    port = int(os.environ.get("PORT", 5000))
    await app.run_task(host="0.0.0.0", port=port)

async def main():
    init_db()
    await asyncio.gather(run_bot(), run_web(), keep_alive())

if __name__ == "__main__":
    asyncio.run(main())
