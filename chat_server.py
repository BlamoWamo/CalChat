#!/usr/bin/env python3
"""
Multi-client chat server with channels, DMs, and database support.
Supports authentication, persistent messages, and multi-channel chat.
"""

import socket
import select
import sys
import sqlite3
import hashlib
import datetime
import threading
from typing import Dict, Optional, Tuple, Set


class ChatDatabase:
    """Handle all database operations."""
    
    def __init__(self, db_path: str = "chat_server.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database schema."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT DEFAULT 'online',
                status_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_activity TIMESTAMP
            )
        """)
        
        # Channels table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        
        # Check if messages table exists and needs migration
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            # Check if old schema (without channel column)
            cursor.execute("PRAGMA table_info(messages)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'channel' not in columns:
                print("⚠ Migrating database to new schema...")
                # Rename old table
                cursor.execute("ALTER TABLE messages RENAME TO messages_old")
                
                # Create new table with correct schema
                cursor.execute("""
                    CREATE TABLE messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        username TEXT NOT NULL,
                        channel TEXT NOT NULL DEFAULT 'general',
                        message TEXT NOT NULL,
                        is_dm BOOLEAN DEFAULT 0,
                        dm_recipient TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                """)
                
                # Copy data from old table
                cursor.execute("""
                    INSERT INTO messages (id, user_id, username, channel, message, timestamp)
                    SELECT id, user_id, username, 'general', message, timestamp
                    FROM messages_old
                """)
                
                # Drop old table
                cursor.execute("DROP TABLE messages_old")
                print("✓ Database migration complete")
        else:
            # Create fresh messages table
            cursor.execute("""
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    channel TEXT NOT NULL DEFAULT 'general',
                    message TEXT NOT NULL,
                    is_dm BOOLEAN DEFAULT 0,
                    dm_recipient TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
        
        # Messages table with reactions and threading
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(message_id, user_id, emoji),
                FOREIGN KEY (message_id) REFERENCES messages(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_reactions_message 
            ON reactions(message_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_dm 
            ON messages(is_dm, dm_recipient, timestamp DESC)
        """)
        
        # Create default channel
        cursor.execute("INSERT OR IGNORE INTO channels (name) VALUES ('general')")
        
        conn.commit()
        conn.close()
        print("✓ Database initialized")
    
    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Register a new user."""
        if len(username) < 3 or len(username) > 20:
            return False, "Username must be 3-20 characters"
        
        if len(password) < 4:
            return False, "Password must be at least 4 characters"
        
        if ' ' in username:
            return False, "Username cannot contain spaces"
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            password_hash = self.hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            return True, "Registration successful"
        except sqlite3.IntegrityError:
            conn.close()
            return False, "Username already exists"
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """Authenticate user."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        password_hash = self.hash_password(password)
        cursor.execute(
            "SELECT id FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash)
        )
        
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            conn.close()
            return True, user_id
        
        conn.close()
        return False, None
    
    def save_message(self, user_id: int, username: str, channel: str, message: str, 
                     is_dm: bool = False, dm_recipient: str = None, parent_id: int = None) -> int:
        """Save a message to the database. Returns message ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if we have threading columns
        cursor.execute("PRAGMA table_info(messages)")
        columns = [row[1] for row in cursor.fetchall()]
        has_threading = 'parent_id' in columns
        
        if has_threading:
            cursor.execute(
                """INSERT INTO messages (user_id, username, channel, message, is_dm, dm_recipient, parent_id) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, username, channel, message, is_dm, dm_recipient, parent_id)
            )
            
            message_id = cursor.lastrowid
            
            # Update thread count on parent if this is a reply
            if parent_id:
                cursor.execute(
                    "UPDATE messages SET thread_count = thread_count + 1 WHERE id = ?",
                    (parent_id,)
                )
        else:
            # Fallback for old schema
            cursor.execute(
                """INSERT INTO messages (user_id, username, channel, message, is_dm, dm_recipient) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, username, channel, message, is_dm, dm_recipient)
            )
            message_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        return message_id
    
    def get_channel_messages(self, channel: str, limit: int = 50) -> list:
        """Get recent messages from a channel with reactions."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if we have the new columns
        cursor.execute("PRAGMA table_info(messages)")
        columns = [row[1] for row in cursor.fetchall()]
        has_threading = 'parent_id' in columns
        
        if has_threading:
            cursor.execute("""
                SELECT m.id, m.username, m.message, m.timestamp, m.parent_id, m.thread_count,
                       GROUP_CONCAT(r.emoji || ':' || r.username) as reactions
                FROM messages m
                LEFT JOIN reactions r ON m.id = r.message_id
                WHERE m.channel = ? AND m.is_dm = 0
                GROUP BY m.id
                ORDER BY m.timestamp DESC 
                LIMIT ?
            """, (channel, limit))
        else:
            # Fallback for old schema
            cursor.execute("""
                SELECT m.id, m.username, m.message, m.timestamp, NULL as parent_id, 0 as thread_count,
                       NULL as reactions
                FROM messages m
                WHERE m.channel = ? AND m.is_dm = 0
                ORDER BY m.timestamp DESC 
                LIMIT ?
            """, (channel, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return list(reversed(messages))
    
    def get_dm_messages(self, user1: str, user2: str, limit: int = 50) -> list:
        """Get DM history between two users."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, message, timestamp 
            FROM messages 
            WHERE is_dm = 1 AND (
                (username = ? AND dm_recipient = ?) OR 
                (username = ? AND dm_recipient = ?)
            )
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (user1, user2, user2, user1, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return list(reversed(messages))
    
    def create_channel(self, name: str, created_by: int) -> Tuple[bool, str]:
        """Create a new channel."""
        if ' ' in name or len(name) < 2 or len(name) > 30:
            return False, "Invalid channel name"
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO channels (name, created_by) VALUES (?, ?)",
                (name, created_by)
            )
            conn.commit()
            conn.close()
            return True, f"Channel #{name} created"
        except sqlite3.IntegrityError:
            conn.close()
            return False, "Channel already exists"
    
    def update_user_activity(self, user_id: int):
        """Update user's last activity timestamp."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        
        conn.commit()
        conn.close()
    
    def set_user_status(self, user_id: int, status: str, status_message: str = None) -> bool:
        """Set user's status. Status can be: online, away, busy, dnd"""
        valid_statuses = ['online', 'away', 'busy', 'dnd']
        if status not in valid_statuses:
            return False
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if status_message:
            cursor.execute(
                "UPDATE users SET status = ?, status_message = ? WHERE id = ?",
                (status, status_message, user_id)
            )
        else:
            cursor.execute(
                "UPDATE users SET status = ? WHERE id = ?",
                (status, user_id)
            )
        
        conn.commit()
        conn.close()
        return True
    
    def get_user_status(self, username: str) -> Optional[dict]:
        """Get user's status information."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT status, status_message, last_activity 
               FROM users WHERE username = ?""",
            (username,)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'status': result[0],
                'status_message': result[1],
                'last_activity': result[2]
            }
        return None
    
    def add_reaction(self, message_id: int, user_id: int, username: str, emoji: str) -> bool:
        """Add a reaction to a message."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if reactions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reactions'")
        if not cursor.fetchone():
            conn.close()
            return False  # Reactions not supported
        
        try:
            cursor.execute(
                "INSERT INTO reactions (message_id, user_id, username, emoji) VALUES (?, ?, ?, ?)",
                (message_id, user_id, username, emoji)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            # Already reacted with this emoji
            conn.close()
            return False
    
    def remove_reaction(self, message_id: int, user_id: int, emoji: str) -> bool:
        """Remove a reaction from a message."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if reactions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reactions'")
        if not cursor.fetchone():
            conn.close()
            return False  # Reactions not supported
        
        cursor.execute(
            "DELETE FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
            (message_id, user_id, emoji)
        )
        
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
    
    def get_reactions(self, message_id: int) -> dict:
        """Get all reactions for a message grouped by emoji."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if reactions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reactions'")
        if not cursor.fetchone():
            conn.close()
            return {}  # Reactions not supported
        
        cursor.execute(
            "SELECT emoji, username FROM reactions WHERE message_id = ?",
            (message_id,)
        )
        
        reactions = {}
        for row in cursor.fetchall():
            emoji, username = row
            if emoji not in reactions:
                reactions[emoji] = []
            reactions[emoji].append(username)
        
        conn.close()
        return reactions
    
    def get_thread_messages(self, parent_id: int) -> list:
        """Get all messages in a thread."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Check if we have threading columns
        cursor.execute("PRAGMA table_info(messages)")
        columns = [row[1] for row in cursor.fetchall()]
        has_threading = 'parent_id' in columns
        
        if not has_threading:
            conn.close()
            return []  # No threading support, return empty
        
        cursor.execute("""
            SELECT id, username, message, timestamp 
            FROM messages 
            WHERE parent_id = ?
            ORDER BY timestamp ASC
        """, (parent_id,))
        
        messages = cursor.fetchall()
        conn.close()
        return messages
    
    def list_channels(self) -> list:
        """List all channels."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM channels ORDER BY name")
        channels = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        return channels


class AuthenticatedClient:
    """Represents an authenticated client connection."""
    
    def __init__(self, sock: socket.socket, user_id: int, username: str):
        self.socket = sock
        self.user_id = user_id
        self.username = username
        self.authenticated = True
        self.current_channel = "general"
        self.typing = False
        self.last_activity = datetime.datetime.now()
        self.status = "online"
        self.last_message_id = None  # Track last message for reactions/replies


class ChatServer:
    """Chat server with channels, DMs, and authentication."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5050, db_path: str = "chat_server.db"):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients: Dict[socket.socket, AuthenticatedClient] = {}
        self.unauthenticated: Dict[socket.socket, dict] = {}
        self.running = False
        self.db = ChatDatabase(db_path)
        self.typing_notifications: Dict[str, Set[str]] = {}  # channel -> set of usernames typing
        
        # Start activity monitor thread
        self.activity_thread = threading.Thread(target=self._monitor_activity, daemon=True)
        self.activity_thread.start()
    
    def start(self):
        """Initialize and start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            channels = self.db.list_channels()
            print(f"✓ Server running on {self.host}:{self.port}")
            print(f"✓ Channels: {', '.join('#' + c for c in channels)}")
            print(f"✓ Presence & typing indicators enabled")
            print(f"✓ Waiting for connections...")
            print(f"✓ Press Ctrl+C to stop\n")
        except OSError as e:
            print(f"✗ Failed to start server: {e}")
            sys.exit(1)
    
    def _monitor_activity(self):
        """Background thread to monitor user activity and update status."""
        import time
        while True:
            time.sleep(30)  # Check every 30 seconds
            
            if not self.running:
                break
            
            now = datetime.datetime.now()
            for client in list(self.clients.values()):
                idle_time = (now - client.last_activity).total_seconds()
                
                # Auto-away after 5 minutes
                if idle_time > 300 and client.status == 'online':
                    client.status = 'away'
                    self.db.set_user_status(client.user_id, 'away')
                    self.broadcast_to_channel(client.current_channel,
                        f"*** {client.username} is now away ***\n")
    
    def handle_typing_indicator(self, client_sock: socket.socket, is_typing: bool):
        """Handle typing indicator from client."""
        client = self.clients.get(client_sock)
        if not client:
            return
        
        channel = client.current_channel
        
        if channel not in self.typing_notifications:
            self.typing_notifications[channel] = set()
        
        if is_typing:
            if client.username not in self.typing_notifications[channel]:
                self.typing_notifications[channel].add(client.username)
                # Notify others in channel
                self.broadcast_to_channel(channel,
                    f"__TYPING__{client.username}__START__\n",
                    sender=client_sock)
        else:
            if client.username in self.typing_notifications[channel]:
                self.typing_notifications[channel].remove(client.username)
                # Notify others in channel
                self.broadcast_to_channel(channel,
                    f"__TYPING__{client.username}__STOP__\n",
                    sender=client_sock)
    
    def broadcast_to_channel(self, channel: str, msg: str, sender: Optional[socket.socket] = None, 
                            include_sender: bool = False):
        """Send message to all clients in a channel."""
        disconnected = []
        
        # Make a copy of the clients dict to avoid modification during iteration
        clients_snapshot = list(self.clients.items())
        
        for client_sock, client in clients_snapshot:
            # Skip if not in the right channel
            if client.current_channel != channel:
                continue
            
            # Skip sender unless include_sender is True
            if client_sock == sender and not include_sender:
                continue
            
            try:
                client_sock.sendall(msg.encode('utf-8'))
            except (BrokenPipeError, OSError, AttributeError):
                disconnected.append(client_sock)
        
        # Clean up disconnected clients
        for sock in disconnected:
            if sock in self.clients:  # Check again in case already removed
                self.remove_client(sock, notify=False)
    
    def send_to_client(self, client_sock: socket.socket, msg: str):
        """Send message to specific client."""
        try:
            client_sock.sendall(msg.encode('utf-8'))
        except (BrokenPipeError, OSError):
            self.remove_client(client_sock, notify=False)
    
    def send_dm(self, from_user: str, to_username: str, message: str):
        """Send direct message to a user."""
        # Find recipient
        recipient_sock = None
        for sock, client in self.clients.items():
            if client.username == to_username:
                recipient_sock = sock
                break
        
        if recipient_sock:
            self.send_to_client(recipient_sock, f"[DM from {from_user}] {message}\n")
            return True
        return False
    
    def handle_new_connection(self):
        """Accept new client connection."""
        try:
            client_sock, addr = self.server_socket.accept()
            
            self.unauthenticated[client_sock] = {
                'address': addr,
                'stage': 'welcome'
            }
            
            print(f"[+] New connection from {addr[0]}:{addr[1]}")
            
            welcome = (
                "=== Welcome to the Chat Server ===\n"
                "Commands:\n"
                "  /register <username> <password> - Create account\n"
                "  /login <username> <password> - Sign in\n"
                "  /quit - Disconnect\n"
            )
            self.send_to_client(client_sock, welcome)
            
        except OSError as e:
            print(f"[!] Error accepting connection: {e}")
    
    def handle_unauthenticated_data(self, client_sock: socket.socket):
        """Handle data from unauthenticated client."""
        try:
            data = client_sock.recv(1024)
            
            if not data:
                del self.unauthenticated[client_sock]
                client_sock.close()
                return
            
            message = data.decode('utf-8', errors='replace').strip()
            parts = message.split()
            
            if not parts:
                return
            
            cmd = parts[0].lower()
            
            if cmd == '/register' and len(parts) == 3:
                username, password = parts[1], parts[2]
                success, msg = self.db.register_user(username, password)
                
                if success:
                    self.send_to_client(client_sock, f"✓ {msg}\n✓ Now use /login {username} <password>\n")
                else:
                    self.send_to_client(client_sock, f"✗ {msg}\n")
            
            elif cmd == '/login' and len(parts) == 3:
                username, password = parts[1], parts[2]
                success, user_id = self.db.authenticate_user(username, password)
                
                if success:
                    for client in self.clients.values():
                        if client.username == username:
                            self.send_to_client(client_sock, "✗ User already logged in\n")
                            return
                    
                    auth_client = AuthenticatedClient(client_sock, user_id, username)
                    self.clients[client_sock] = auth_client
                    del self.unauthenticated[client_sock]
                    
                    print(f"[✓] {username} logged in")
                    
                    self.send_to_client(client_sock, f"✓ Welcome back, {username}!\n")
                    self.send_to_client(client_sock, "✓ Commands: /join, /dm, /channels, /users, /quit\n\n")
                    
                    # Send recent messages from general channel
                    recent = self.db.get_channel_messages("general", limit=20)
                    if recent:
                        self.send_to_client(client_sock, "=== Recent Messages (#general) ===\n")
                        for row in recent:
                            msg_id, username, msg, timestamp, parent_id, thread_count, reactions = row
                            time_str = timestamp.split('.')[0]
                            
                            # Format message with ID and reactions
                            msg_text = f"[{msg_id}] {username}: {msg}"
                            if reactions:
                                reaction_str = self._format_reactions(reactions)
                                msg_text += f" {reaction_str}"
                            if thread_count and thread_count > 0:
                                msg_text += f" [💬 {thread_count} replies]"
                            
                            self.send_to_client(client_sock, f"[{time_str}] {msg_text}\n")
                        self.send_to_client(client_sock, "==================================\n\n")
                    
                    # Notify channel
                    self.broadcast_to_channel("general", f"*** {username} joined #general ***\n")
                else:
                    self.send_to_client(client_sock, "✗ Invalid username or password\n")
            
            elif cmd in ('/quit', '/exit'):
                del self.unauthenticated[client_sock]
                client_sock.close()
            
            else:
                self.send_to_client(client_sock, "✗ Invalid command. Use /register or /login\n")
                
        except (ConnectionResetError, BrokenPipeError, OSError):
            if client_sock in self.unauthenticated:
                del self.unauthenticated[client_sock]
            try:
                client_sock.close()
            except:
                pass
    
    def handle_client_data(self, client_sock: socket.socket):
        """Handle data from authenticated client."""
        client = self.clients.get(client_sock)
        if not client:
            return
        
        try:
            data = client_sock.recv(1024)
            
            if not data:
                self.remove_client(client_sock)
                return
            
            message = data.decode('utf-8', errors='replace').strip()
            
            # Update activity
            client.last_activity = datetime.datetime.now()
            if client.status == 'away':
                client.status = 'online'
                self.db.set_user_status(client.user_id, 'online')
                self.broadcast_to_channel(client.current_channel,
                    f"*** {client.username} is back ***\n")
            
            self.db.update_user_activity(client.user_id)
            
            # Handle typing indicators (special protocol)
            if message == '__TYPING_START__':
                self.handle_typing_indicator(client_sock, True)
                return
            elif message == '__TYPING_STOP__':
                self.handle_typing_indicator(client_sock, False)
                return
            
            if message.startswith('/'):
                self.handle_command(client_sock, message)
            else:
                # Stop typing indicator when message sent
                self.handle_typing_indicator(client_sock, False)
                
                # Regular message - save and broadcast to channel
                message_id = self.db.save_message(client.user_id, client.username, 
                                    client.current_channel, message)
                client.last_message_id = message_id  # Track for reactions
                
                print(f"[{client.username}@{client.current_channel}] {message}")
                
                # Broadcast with message ID for reactions
                self.broadcast_to_channel(client.current_channel, 
                                         f"[{message_id}] {client.username}: {message}\n", 
                                         sender=client_sock, include_sender=True)
                
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.remove_client(client_sock)
    
    def handle_command(self, client_sock: socket.socket, command: str):
        """Handle client commands."""
        client = self.clients[client_sock]
        parts = command.split(None, 2)
        cmd = parts[0].lower()
        
        try:
            if cmd in ('/quit', '/exit', '/q'):
                self.remove_client(client_sock)
            
            elif cmd == '/join' and len(parts) >= 2:
                channel = parts[1].strip()
                
                # Create channel if it doesn't exist
                channels = self.db.list_channels()
                if channel not in channels:
                    success, msg = self.db.create_channel(channel, client.user_id)
                    if not success:
                        self.send_to_client(client_sock, f"*** {msg} ***\n")
                        return
                
                # Leave old channel
                old_channel = client.current_channel
                self.broadcast_to_channel(old_channel, 
                                         f"*** {client.username} left #{old_channel} ***\n")
                
                # Join new channel
                client.current_channel = channel
                self.send_to_client(client_sock, f"*** Joined #{channel} ***\n")
                
                # Send recent messages
                recent = self.db.get_channel_messages(channel, limit=20)
                if recent:
                    for row in recent:
                        msg_id, username, msg, timestamp, parent_id, thread_count, reactions = row
                        time_str = timestamp.split('.')[0]
                        
                        # Format message with reactions
                        msg_text = f"[{msg_id}] {username}: {msg}"
                        if reactions:
                            reaction_str = self._format_reactions(reactions)
                            msg_text += f" {reaction_str}"
                        if thread_count and thread_count > 0:
                            msg_text += f" [💬 {thread_count} replies]"
                        
                        self.send_to_client(client_sock, f"[{time_str}] {msg_text}\n")
                
                # Notify new channel
                self.broadcast_to_channel(channel, 
                                         f"*** {client.username} joined #{channel} ***\n",
                                         sender=client_sock)
            
            elif cmd == '/dm' and len(parts) >= 3:
                to_username = parts[1]
                message = parts[2]
                
                # Save DM
                self.db.save_message(client.user_id, client.username, "DM", 
                                    message, is_dm=True, dm_recipient=to_username)
                
                # Send DM
                if self.send_dm(client.username, to_username, message):
                    self.send_to_client(client_sock, f"[DM to {to_username}] {message}\n")
                else:
                    self.send_to_client(client_sock, f"*** User {to_username} not online ***\n")
            
            elif cmd == '/channels':
                channels = self.db.list_channels()
                channel_list = ", ".join("#" + c for c in channels)
                self.send_to_client(client_sock, f"*** Channels: {channel_list} ***\n")
            
            elif cmd == '/users':
                users_in_channel = []
                for c in self.clients.values():
                    if c.current_channel == client.current_channel:
                        status_icon = {'online': '🟢', 'away': '🟡', 'busy': '🔴', 'dnd': '⛔'}.get(c.status, '⚪')
                        user_status = self.db.get_user_status(c.username)
                        status_msg = f" - {user_status['status_message']}" if user_status and user_status['status_message'] else ""
                        users_in_channel.append(f"{status_icon} {c.username}{status_msg}")
                
                user_list = "\n  ".join(sorted(users_in_channel))
                count = len(users_in_channel)
                self.send_to_client(client_sock, 
                    f"*** Users in #{client.current_channel} ({count}) ***\n  {user_list}\n")
            
            elif cmd == '/status' and len(parts) >= 2:
                # /status <online|away|busy|dnd> [message]
                new_status = parts[1].lower()
                status_message = parts[2] if len(parts) >= 3 else None
                
                if self.db.set_user_status(client.user_id, new_status, status_message):
                    client.status = new_status
                    msg = f"*** Status set to {new_status}"
                    if status_message:
                        msg += f": {status_message}"
                    msg += " ***\n"
                    self.send_to_client(client_sock, msg)
                    
                    # Notify channel
                    status_text = f"{new_status}"
                    if status_message:
                        status_text += f" ({status_message})"
                    self.broadcast_to_channel(client.current_channel,
                        f"*** {client.username} is now {status_text} ***\n")
                else:
                    self.send_to_client(client_sock, 
                        "*** Invalid status. Use: online, away, busy, or dnd ***\n")
            
            elif cmd == '/whois' and len(parts) >= 2:
                target_username = parts[1]
                user_status = self.db.get_user_status(target_username)
                
                if user_status:
                    status_icon = {'online': '🟢', 'away': '🟡', 'busy': '🔴', 'dnd': '⛔'}.get(user_status['status'], '⚪')
                    info = f"*** Info for {target_username} ***\n"
                    info += f"Status: {status_icon} {user_status['status']}\n"
                    if user_status['status_message']:
                        info += f"Message: {user_status['status_message']}\n"
                    if user_status['last_activity']:
                        info += f"Last active: {user_status['last_activity']}\n"
                    self.send_to_client(client_sock, info)
                else:
                    self.send_to_client(client_sock, f"*** User {target_username} not found ***\n")
            
            elif cmd == '/react' and len(parts) >= 3:
                # /react <message_id> <emoji>
                try:
                    msg_id = int(parts[1])
                    emoji = parts[2]
                    
                    if self.db.add_reaction(msg_id, client.user_id, client.username, emoji):
                        # Broadcast reaction to channel
                        self.broadcast_to_channel(client.current_channel,
                            f"__REACTION__{msg_id}__{emoji}__{client.username}__\n",
                            include_sender=True)
                    else:
                        self.send_to_client(client_sock, "*** You already reacted with that emoji ***\n")
                except ValueError:
                    self.send_to_client(client_sock, "*** Invalid message ID ***\n")
            
            elif cmd == '/unreact' and len(parts) >= 3:
                # /unreact <message_id> <emoji>
                try:
                    msg_id = int(parts[1])
                    emoji = parts[2]
                    
                    if self.db.remove_reaction(msg_id, client.user_id, emoji):
                        # Broadcast unreaction to channel
                        self.broadcast_to_channel(client.current_channel,
                            f"__UNREACTION__{msg_id}__{emoji}__{client.username}__\n",
                            include_sender=True)
                    else:
                        self.send_to_client(client_sock, "*** You haven't reacted with that emoji ***\n")
                except ValueError:
                    self.send_to_client(client_sock, "*** Invalid message ID ***\n")
            
            elif cmd == '/reply' and len(parts) >= 3:
                # /reply <message_id> <message>
                try:
                    parent_id = int(parts[1])
                    reply_msg = parts[2]
                    
                    # Save reply
                    msg_id = self.db.save_message(client.user_id, client.username,
                                                   client.current_channel, reply_msg,
                                                   parent_id=parent_id)
                    
                    # Broadcast reply
                    self.broadcast_to_channel(client.current_channel,
                        f"[{msg_id}] ↳ {client.username}: {reply_msg}\n",
                        include_sender=True)
                except ValueError:
                    self.send_to_client(client_sock, "*** Invalid message ID ***\n")
            
            elif cmd == '/thread' and len(parts) >= 2:
                # /thread <message_id> - View thread
                try:
                    parent_id = int(parts[1])
                    thread = self.db.get_thread_messages(parent_id)
                    
                    if thread:
                        self.send_to_client(client_sock, f"=== Thread ({len(thread)} replies) ===\n")
                        for row in thread:
                            msg_id, username, msg, timestamp = row
                            time_str = timestamp.split('.')[0]
                            self.send_to_client(client_sock, f"[{time_str}] [{msg_id}] {username}: {msg}\n")
                        self.send_to_client(client_sock, "=========================\n")
                    else:
                        self.send_to_client(client_sock, "*** No replies in this thread ***\n")
                except ValueError:
                    self.send_to_client(client_sock, "*** Invalid message ID ***\n")
            
            else:
                self.send_to_client(client_sock, 
                    "*** Unknown command. Try /join, /dm, /channels, /users, /status, /whois, /react, /reply, /thread, or /quit ***\n")
                
        except (BrokenPipeError, OSError):
            self.remove_client(client_sock, notify=False)
    
    def _format_reactions(self, reactions_str: str) -> str:
        """Format reactions string from database."""
        if not reactions_str:
            return ""
        
        reactions = {}
        for item in reactions_str.split(','):
            if ':' in item:
                emoji, username = item.split(':', 1)
                if emoji not in reactions:
                    reactions[emoji] = []
                reactions[emoji].append(username)
        
        # Format as: 👍(3) ❤️(2)
        result = []
        for emoji, users in reactions.items():
            result.append(f"{emoji}({len(users)})")
        
        return " ".join(result) if result else ""
    
    def remove_client(self, client_sock: socket.socket, notify: bool = True):
        """Remove authenticated client."""
        if client_sock not in self.clients:
            # Already removed
            return
        
        client = self.clients[client_sock]
        print(f"[-] {client.username} disconnected")
        
        if notify:
            try:
                self.broadcast_to_channel(client.current_channel, 
                                         f"*** {client.username} left the chat ***\n")
            except Exception as e:
                print(f"[!] Error broadcasting disconnect: {e}")
        
        # Remove from clients dict first
        del self.clients[client_sock]
        
        # Close socket
        try:
            client_sock.close()
        except:
            pass
    
    def run(self):
        """Main server loop."""
        try:
            while self.running:
                all_sockets = [self.server_socket] + list(self.clients.keys()) + list(self.unauthenticated.keys())
                
                try:
                    readable, _, exceptional = select.select(all_sockets, [], all_sockets, 1.0)
                except (ValueError, OSError):
                    continue
                
                for sock in readable:
                    if sock is self.server_socket:
                        self.handle_new_connection()
                    elif sock in self.unauthenticated:
                        self.handle_unauthenticated_data(sock)
                    elif sock in self.clients:
                        self.handle_client_data(sock)
                
                for sock in exceptional:
                    if sock in self.clients:
                        self.remove_client(sock)
                    elif sock in self.unauthenticated:
                        del self.unauthenticated[sock]
                        try:
                            sock.close()
                        except:
                            pass
                        
        except KeyboardInterrupt:
            print("\n\n[!] Server shutdown requested...")
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Clean shutdown of server."""
        print("[!] Shutting down server...")
        
        for client_sock in list(self.clients.keys()):
            try:
                client_sock.sendall(b"*** Server is shutting down ***\n")
                client_sock.close()
            except:
                pass
        
        for sock in list(self.unauthenticated.keys()):
            try:
                sock.close()
            except:
                pass
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("[✓] Server stopped")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Chat server with channels and DMs")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5050, help="Port to bind to")
    parser.add_argument("--db", default="chat_server.db", help="Database file path")
    args = parser.parse_args()
    
    server = ChatServer(host=args.host, port=args.port, db_path=args.db)
    server.start()
    server.run()


if __name__ == "__main__":
    main()
