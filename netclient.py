#!/usr/bin/env python3
"""
Terminal-based chat client with DMs and channels support.
Connects to a chat server and provides multi-channel messaging.
"""

import socket
import threading
import curses
import sys
import re
import os
import subprocess
from typing import List
from collections import deque


class NotificationManager:
    """Handle desktop notifications across different platforms."""
    
    def __init__(self):
        self.enabled = True
        self.sound_enabled = True
        self.platform = sys.platform
        self.method = None
        self.notify2_available = False
        try:
            self._check_availability()
        except Exception as e:
            self.enabled = False
            self.method = None
    
    def _check_availability(self):
        """Check if notifications are available on this platform."""
        if self.platform == "darwin":  # macOS
            # osascript is built-in
            self.method = "osascript"
        elif self.platform.startswith("linux"):
            # Try libnotify (notify2) first, then notify-send
            try:
                import notify2
                notify2.init("ChatClient")
                self.notify2_available = True
                self.method = "libnotify"
            except (ImportError, Exception):
                # Fall back to notify-send
                try:
                    subprocess.run(["which", "notify-send"], 
                                 capture_output=True, check=True)
                    self.method = "notify-send"
                except (subprocess.CalledProcessError, FileNotFoundError):
                    self.enabled = False
                    self.method = None
        elif self.platform == "win32":
            # Use PowerShell on Windows
            self.method = "powershell"
        else:
            self.enabled = False
            self.method = None
    
    def send(self, title: str, message: str, urgency: str = "normal"):
        """
        Send a desktop notification.
        urgency: 'low', 'normal', 'critical'
        """
        if not self.enabled:
            return
        
        try:
            if self.method == "libnotify":
                # Linux with libnotify (notify2)
                import notify2
                
                # Map urgency levels
                urgency_map = {
                    'low': notify2.URGENCY_LOW,
                    'normal': notify2.URGENCY_NORMAL,
                    'critical': notify2.URGENCY_CRITICAL
                }
                
                n = notify2.Notification(title, message, "dialog-information")
                n.set_urgency(urgency_map.get(urgency, notify2.URGENCY_NORMAL))
                n.show()
            
            elif self.method == "notify-send":
                # Linux with notify-send
                subprocess.Popen([
                    "notify-send",
                    "-u", urgency,
                    "-i", "dialog-information",
                    title,
                    message
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            elif self.method == "osascript":
                # macOS
                script = f'display notification "{message}" with title "{title}"'
                subprocess.Popen([
                    "osascript", "-e", script
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            elif self.method == "powershell":
                # Windows
                script = f'''
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
                $template = @"
                <toast>
                    <visual>
                        <binding template="ToastText02">
                            <text id="1">{title}</text>
                            <text id="2">{message}</text>
                        </binding>
                    </visual>
                </toast>
"@
                $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
                $xml.LoadXml($template)
                $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ChatClient")
                $notifier.Show($toast)
                '''
                subprocess.Popen([
                    "powershell", "-Command", script
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        except Exception as e:
            # Silently fail - don't disrupt the chat
            pass
    
    def play_sound(self):
        """Play notification sound."""
        if not self.sound_enabled:
            return
        
        try:
            if self.platform == "darwin":
                subprocess.Popen(["afplay", "/System/Library/Sounds/Ping.aiff"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif self.platform.startswith("linux"):
                # Try paplay (PulseAudio), then aplay (ALSA)
                try:
                    subprocess.Popen(["paplay", "/usr/share/sounds/freedesktop/stereo/message.oga"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    try:
                        subprocess.Popen(["aplay", "/usr/share/sounds/sound-icons/xylofon.wav"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except FileNotFoundError:
                        pass
            elif self.platform == "win32":
                # Use Windows beep
                import winsound
                winsound.MessageBeep(winsound.MB_OK)
        except Exception:
            pass


class MarkdownFormatter:
    """Format markdown text for terminal display with curses."""
    
    @staticmethod
    def parse_and_format(stdscr, y, x, text, max_width):
        """
        Parse markdown and render with formatting.
        Supports: **bold**, *italic*, `code`, @mentions, URLs
        Returns the number of lines used.
        """
        if not text:
            return 0
        
        # Track current position
        current_x = x
        current_y = y
        lines_used = 0
        
        # Parse markdown patterns
        patterns = [
            (r'\*\*(.+?)\*\*', curses.A_BOLD),           # **bold**
            (r'\*(.+?)\*', curses.A_UNDERLINE),          # *italic* (underline in terminal)
            (r'`(.+?)`', curses.A_REVERSE),              # `code`
            (r'@(\w+)', curses.A_BOLD | curses.color_pair(1) if curses.has_colors() else curses.A_BOLD),  # @mention
        ]
        
        # Split text into segments with their formatting
        segments = []
        pos = 0
        
        while pos < len(text):
            # Find next formatting marker
            next_match = None
            next_pattern = None
            next_attr = None
            
            for pattern, attr in patterns:
                match = re.search(pattern, text[pos:])
                if match and (next_match is None or match.start() < next_match.start()):
                    next_match = match
                    next_pattern = pattern
                    next_attr = attr
            
            if next_match:
                # Add plain text before match
                if next_match.start() > 0:
                    segments.append((text[pos:pos + next_match.start()], curses.A_NORMAL))
                
                # Add formatted text
                formatted_text = next_match.group(1)
                segments.append((formatted_text, next_attr))
                
                pos += next_match.end()
            else:
                # No more formatting, add rest as plain text
                segments.append((text[pos:], curses.A_NORMAL))
                break
        
        # Render segments
        try:
            for seg_text, attr in segments:
                words = seg_text.split(' ')
                
                for i, word in enumerate(words):
                    word_len = len(word)
                    space_len = 1 if i < len(words) - 1 else 0
                    
                    # Check if we need to wrap
                    if current_x + word_len > max_width:
                        current_y += 1
                        current_x = x
                        lines_used += 1
                    
                    # Draw the word
                    if current_y < curses.LINES - 1:
                        stdscr.addstr(current_y, current_x, word[:max_width - current_x], attr)
                    
                    current_x += word_len
                    
                    # Add space
                    if space_len and current_x < max_width:
                        if current_y < curses.LINES - 1:
                            stdscr.addstr(current_y, current_x, ' ', curses.A_NORMAL)
                        current_x += space_len
            
        except curses.error:
            pass
        
        return lines_used + 1


class ChatClient:
    """Chat client with threaded message handling and channel support."""
    
    def __init__(self, host: str, port: int, max_messages: int = 1000):
        self.host = host
        self.port = port
        self.messages = deque(maxlen=max_messages)
        self.messages_lock = threading.Lock()
        self.sock = None
        self.running = True
        self.authenticated = False
        self.current_channel = "general"
        self.username = None
        self.typing_users = set()  # Users currently typing
        self.is_typing = False
        self.last_keypress = 0
        
    def connect(self):
        """Establish connection to the server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10.0)
        try:
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(None)
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return False
    
    def listen_to_server(self):
        """Background thread to receive messages from server."""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    self._add_message("*** Server closed connection ***")
                    self.running = False
                    break
                
                incoming = data.decode('utf-8', errors='replace').rstrip()
                
                # Handle typing indicators (special protocol)
                if incoming.startswith("__TYPING__"):
                    parts = incoming.split("__")
                    if len(parts) >= 4:
                        username = parts[2]
                        action = parts[3]
                        
                        if action == "START":
                            self.typing_users.add(username)
                        elif action == "STOP":
                            self.typing_users.discard(username)
                    continue
                
                # Handle reaction updates
                if incoming.startswith("__REACTION__"):
                    parts = incoming.split("__")
                    if len(parts) >= 5:
                        msg_id = parts[2]
                        emoji = parts[3]
                        username = parts[4]
                        self._add_message(f"*** {username} reacted {emoji} to message {msg_id} ***")
                    continue
                
                if incoming.startswith("__UNREACTION__"):
                    parts = incoming.split("__")
                    if len(parts) >= 5:
                        msg_id = parts[2]
                        emoji = parts[3]
                        username = parts[4]
                        self._add_message(f"*** {username} removed {emoji} from message {msg_id} ***")
                    continue
                
                # Add message to display
                self._add_message(incoming)
                
                # Check for notifications (only if authenticated)
                if not hasattr(self, 'notifications_enabled'):
                    continue
                    
                if self.notifications_enabled and not self.window_focused:
                    # Check for @mentions
                    if self.mention_notifications and self.username and f"@{self.username}" in incoming:
                        self.notifications.send(
                            "Chat Mention",
                            f"You were mentioned: {incoming[:100]}",
                            urgency="normal"
                        )
                        self.notifications.play_sound()
                    
                    # Check for DMs
                    elif self.dm_notifications and incoming.startswith("[DM from"):
                        sender = incoming.split()[2].rstrip(']')
                        self.notifications.send(
                            f"Direct Message from {sender}",
                            incoming[incoming.find(']')+2:100],
                            urgency="critical"
                        )
                        self.notifications.play_sound()
                    
                    # Regular channel messages (if user wants all notifications)
                    elif self.notifications_enabled and not incoming.startswith("***"):
                        # Only notify for actual messages, not system messages
                        if ': ' in incoming and not incoming.startswith('['):
                            username = incoming.split(':')[0]
                            if username != self.username:
                                self.notifications.send(
                                    f"#{self.current_channel}",
                                    incoming[:100],
                                    urgency="low"
                                )
                
            except ConnectionResetError:
                self._add_message("*** Connection lost ***")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    self._add_message(f"*** Error: {str(e)} ***")
                break
    
    def _add_message(self, msg: str):
        """Thread-safe message addition."""
        with self.messages_lock:
            self.messages.append(msg)
    
    def send_message(self, msg: str) -> bool:
        """Send a message to the server."""
        try:
            self.sock.sendall(msg.encode('utf-8'))
            return True
        except (OSError, BrokenPipeError):
            return False
    
    def disconnect(self):
        """Clean disconnect from server."""
        self.running = False
        if self.sock:
            try:
                self.sock.sendall(b"/quit")
            except:
                pass
            finally:
                self.sock.close()


class AuthUI:
    """Authentication screen UI."""
    
    def __init__(self, client: ChatClient):
        self.client = client
        self.mode = "menu"
        self.username_buffer = ""
        self.password_buffer = ""
        self.input_field = "username"
        
    def draw(self, stdscr):
        """Draw the authentication UI."""
        height, width = stdscr.getmaxyx()
        
        for i in range(height):
            stdscr.move(i, 0)
            stdscr.clrtoeol()
        
        title = "=== Chat Client Authentication ==="
        try:
            stdscr.addstr(1, (width - len(title)) // 2, title, curses.A_BOLD)
        except curses.error:
            pass
        
        if self.mode == "menu":
            options = [
                "",
                "1. Login to existing account",
                "2. Register new account",
                "3. Quit",
                "",
                "Enter your choice (1-3):"
            ]
            for i, opt in enumerate(options):
                try:
                    stdscr.addstr(4 + i, 4, opt)
                except curses.error:
                    pass
        
        elif self.mode in ("register", "login"):
            action = "Register" if self.mode == "register" else "Login"
            try:
                stdscr.addstr(4, 4, f"=== {action} ===")
                stdscr.addstr(6, 4, "Username: " + self.username_buffer)
                stdscr.addstr(7, 4, "Password: " + ("*" * len(self.password_buffer)))
                stdscr.addstr(9, 4, "Press ENTER to submit, ESC to cancel")
                
                if self.input_field == "username":
                    stdscr.addstr(6, 4, "Username: ", curses.A_BOLD)
                else:
                    stdscr.addstr(7, 4, "Password: ", curses.A_BOLD)
                    
            except curses.error:
                pass
        
        with self.client.messages_lock:
            recent = list(self.client.messages)[-5:]
        
        msg_start = height - 7
        try:
            stdscr.addstr(msg_start, 0, "─" * (width - 1))
        except curses.error:
            pass
        
        for i, msg in enumerate(recent):
            try:
                stdscr.addstr(msg_start + 1 + i, 0, msg[:width-1])
            except curses.error:
                pass
        
        stdscr.refresh()
    
    def handle_input(self, key: int) -> bool:
        """Handle keyboard input."""
        if self.mode == "menu":
            if key == ord('1'):
                self.mode = "login"
                self.username_buffer = ""
                self.password_buffer = ""
                self.input_field = "username"
            elif key == ord('2'):
                self.mode = "register"
                self.username_buffer = ""
                self.password_buffer = ""
                self.input_field = "username"
            elif key == ord('3'):
                return False
        
        elif self.mode in ("register", "login"):
            if key == 27:
                self.mode = "menu"
            elif key == 9:
                self.input_field = "password" if self.input_field == "username" else "username"
            elif key in (10, 13, curses.KEY_ENTER):
                if self.input_field == "username" and self.username_buffer:
                    self.input_field = "password"
                elif self.input_field == "password" and self.username_buffer and self.password_buffer:
                    cmd = "/register" if self.mode == "register" else "/login"
                    self.client.send_message(f"{cmd} {self.username_buffer} {self.password_buffer}")
                    self.client.username = self.username_buffer
                    
                    import time
                    time.sleep(0.5)
                    
                    self.mode = "menu"
                    self.username_buffer = ""
                    self.password_buffer = ""
                    self.input_field = "username"
            elif key in (curses.KEY_BACKSPACE, 127, 8, ord('\b')):
                if self.input_field == "username" and self.username_buffer:
                    self.username_buffer = self.username_buffer[:-1]
                elif self.input_field == "password" and self.password_buffer:
                    self.password_buffer = self.password_buffer[:-1]
            elif 32 <= key <= 126:
                char = chr(key)
                if self.input_field == "username" and len(self.username_buffer) < 20:
                    self.username_buffer += char
                elif self.input_field == "password" and len(self.password_buffer) < 50:
                    self.password_buffer += char
        
        return True
    
    def run(self, stdscr):
        """Main authentication UI loop."""
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(100)
        curses.noecho()
        curses.cbreak()
        
        last_draw_time = 0
        import time
        
        while self.client.running:
            current_time = time.time()
            needs_draw = (current_time - last_draw_time) > 0.1
            
            try:
                key = stdscr.getch()
            except KeyboardInterrupt:
                return False
            
            if key != -1:
                if not self.handle_input(key):
                    return False
                needs_draw = True
            
            with self.client.messages_lock:
                if len(self.client.messages) > 0:
                    needs_draw = True
            
            if needs_draw:
                self.draw(stdscr)
                last_draw_time = current_time
            
            with self.client.messages_lock:
                for msg in self.client.messages:
                    if "Welcome back" in msg or "=== Recent Messages ===" in msg:
                        return True
        
        return False


class ChatUI:
    """Curses-based UI for the chat client with channels."""
    
    def __init__(self, client: ChatClient):
        self.client = client
        self.input_buffer = ""
        self.scroll_offset = 0
        self.last_message_count = 0
        self.needs_redraw = True
        self.formatter = MarkdownFormatter()
        
    def draw(self, stdscr):
        """Draw the UI."""
        height, width = stdscr.getmaxyx()
        
        # Make sure we have enough room
        if height < 10:
            stdscr.clear()
            stdscr.addstr(0, 0, "Terminal too small! Need at least 10 lines.")
            stdscr.refresh()
            return
        
        chat_height = height - 4  # Reserve 4 lines: typing, status, separator, input
        
        with self.client.messages_lock:
            all_messages = list(self.client.messages)
        
        total_messages = len(all_messages)
        start_idx = max(0, total_messages - chat_height - self.scroll_offset)
        end_idx = total_messages - self.scroll_offset
        visible_messages = all_messages[start_idx:end_idx]
        
        # Draw messages with markdown formatting
        current_line = 0
        for msg in visible_messages:
            if current_line >= chat_height:
                break
            
            try:
                stdscr.move(current_line, 0)
                stdscr.clrtoeol()
                
                # Check if this is a message with ID format: "[ID] username: message"
                if msg.startswith('[') and ']' in msg:
                    # Extract message ID
                    id_end = msg.find(']')
                    msg_id = msg[1:id_end]
                    rest = msg[id_end+2:] if len(msg) > id_end+2 else msg[id_end+1:]  # Skip "] " or "]"
                    
                    # Draw message ID in cyan
                    try:
                        stdscr.addstr(current_line, 0, f"[{msg_id}]", 
                                    curses.color_pair(1) if curses.has_colors() else curses.A_DIM)
                    except curses.error:
                        pass
                    
                    id_len = len(f"[{msg_id}] ")
                    
                    # Check if it's a reply (starts with ↳)
                    if rest.startswith('↳ '):
                        try:
                            stdscr.addstr(current_line, id_len, '↳ ', curses.A_DIM)
                        except curses.error:
                            pass
                        id_len += 2
                        rest = rest[2:]
                    
                    # Now parse username and message
                    if ': ' in rest:
                        parts = rest.split(': ', 1)
                        if len(parts) == 2:
                            username, message = parts
                            
                            # Draw username in bold
                            try:
                                stdscr.addstr(current_line, id_len, username + ': ', curses.A_BOLD)
                            except curses.error:
                                pass
                            username_len = id_len + len(username) + 2
                            
                            # Draw message with markdown formatting
                            lines = self.formatter.parse_and_format(
                                stdscr, current_line, username_len, message, width - 1
                            )
                            current_line += max(1, lines)
                        else:
                            # Fallback - just display what we have
                            try:
                                stdscr.addstr(current_line, id_len, rest[:width-1-id_len])
                            except curses.error:
                                pass
                            current_line += 1
                    else:
                        # No colon - might be a system message with ID
                        try:
                            stdscr.addstr(current_line, id_len, rest[:width-1-id_len])
                        except curses.error:
                            pass
                        current_line += 1
                
                elif ': ' in msg and not msg.startswith('***'):
                    # Old format without ID (for compatibility) or timestamp format
                    # Check if it starts with a timestamp like [2025-11-26
                    if msg.startswith('[20'):
                        # Has timestamp, skip it
                        timestamp_end = msg.find(']')
                        if timestamp_end > 0:
                            msg = msg[timestamp_end+2:]  # Skip timestamp
                    
                    parts = msg.split(': ', 1)
                    if len(parts) == 2:
                        username, message = parts
                        
                        # Draw username in bold
                        try:
                            stdscr.addstr(current_line, 0, username + ': ', curses.A_BOLD)
                        except curses.error:
                            pass
                        username_len = len(username) + 2
                        
                        # Draw message with markdown formatting
                        lines = self.formatter.parse_and_format(
                            stdscr, current_line, username_len, message, width - 1
                        )
                        current_line += max(1, lines)
                    else:
                        # Fallback to plain text
                        display_msg = msg[:width-1]
                        try:
                            stdscr.addstr(current_line, 0, display_msg)
                        except curses.error:
                            pass
                        current_line += 1
                else:
                    # System messages and other text - display normally
                    display_msg = msg[:width-1]
                    
                    # Color system messages
                    try:
                        if msg.startswith('***'):
                            stdscr.addstr(current_line, 0, display_msg, curses.A_DIM)
                        elif msg.startswith('[DM'):
                            stdscr.addstr(current_line, 0, display_msg, curses.A_BOLD | curses.color_pair(2) if curses.has_colors() else curses.A_BOLD)
                        else:
                            stdscr.addstr(current_line, 0, display_msg)
                    except curses.error:
                        pass
                    
                    current_line += 1
                    
            except curses.error:
                current_line += 1
            except Exception as e:
                # Fallback for any parsing errors - just show the raw message
                try:
                    stdscr.addstr(current_line, 0, msg[:width-1])
                except:
                    pass
                current_line += 1
        
        # Clear remaining lines in chat area
        while current_line < chat_height:
            try:
                stdscr.move(current_line, 0)
                stdscr.clrtoeol()
                current_line += 1
            except curses.error:
                break
        
        # Line for typing indicator (height - 4)
        typing_line = height - 4
        try:
            stdscr.move(typing_line, 0)
            stdscr.clrtoeol()
            if self.client.typing_users:
                typing_text = ", ".join(sorted(self.client.typing_users))
                if len(typing_text) > 40:
                    typing_text = typing_text[:37] + "..."
                typing_msg = f"{typing_text} {'is' if len(self.client.typing_users) == 1 else 'are'} typing..."
                stdscr.addstr(typing_line, 0, typing_msg[:width-1], curses.A_DIM)
        except curses.error:
            pass
        
        # Status bar with channel info (height - 3)
        status_line = height - 3
        try:
            stdscr.move(status_line, 0)
            status = f" Channel: #{self.client.current_channel} | Markdown: **bold** *italic* `code` @user "
            # Pad to full width and reverse video
            status_padded = status + " " * max(0, width - len(status) - 1)
            stdscr.addstr(status_line, 0, status_padded[:width-1], curses.A_REVERSE)
        except curses.error:
            pass
        
        # Separator (height - 2)
        sep_line = height - 2
        try:
            stdscr.move(sep_line, 0)
            stdscr.addstr("─" * min(width - 1, width))
        except curses.error:
            pass
        
        # Input line (height - 1)
        input_line = height - 1
        prompt = "> "
        input_display = self.input_buffer[-(width - len(prompt) - 1):]
        try:
            stdscr.move(input_line, 0)
            stdscr.clrtoeol()
            stdscr.addstr(input_line, 0, prompt + input_display)
            stdscr.move(input_line, min(len(prompt) + len(input_display), width - 1))
        except curses.error:
            pass
        
        stdscr.refresh()
    
    def handle_input(self, key: int) -> bool:
        """Handle keyboard input."""
        if key in (10, 13, curses.KEY_ENTER):
            msg = self.input_buffer.strip()
            
            if msg.lower() in ("/quit", "/exit", "/q"):
                return False
            
            # Handle channel/DM commands
            if msg.lower().startswith("/join "):
                channel = msg.split(None, 1)[1].strip()
                if channel:
                    self.client.send_message(f"/join {channel}")
                    self.client.current_channel = channel
            elif msg.lower().startswith("/dm "):
                # Format: /dm username message
                parts = msg.split(None, 2)
                if len(parts) >= 3:
                    self.client.send_message(msg)
                elif len(parts) == 2:
                    self.client._add_message("*** Usage: /dm <username> <message> ***")
            elif msg.lower() == "/channels":
                self.client.send_message("/channels")
            elif msg:
                # Regular message
                if self.client.send_message(msg):
                    pass
                else:
                    self.client._add_message("*** Failed to send message ***")
            
            self.input_buffer = ""
            self.scroll_offset = 0
            self.needs_redraw = True
            
        elif key in (curses.KEY_BACKSPACE, 127, 8, ord('\b')):
            if self.input_buffer:
                self.input_buffer = self.input_buffer[:-1]
                self.needs_redraw = True
        
        elif key == curses.KEY_UP:
            self.scroll_offset = min(self.scroll_offset + 1, len(self.client.messages) - 1)
            self.needs_redraw = True
        
        elif key == curses.KEY_DOWN:
            self.scroll_offset = max(self.scroll_offset - 1, 0)
            self.needs_redraw = True
        
        elif 32 <= key <= 126:
            self.input_buffer += chr(key)
            self.needs_redraw = True
        
        return True
    
    def run(self, stdscr):
        """Main UI loop."""
        curses.curs_set(1)
        stdscr.nodelay(True)
        stdscr.timeout(100)
        curses.noecho()
        curses.cbreak()
        
        # Initialize colors if available
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)    # @mentions
            curses.init_pair(2, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # DMs
        
        # Show help on startup
        self.client._add_message("")
        self.client._add_message("=== Commands ===")
        self.client._add_message("/join <channel> - Switch to a channel")
        self.client._add_message("/dm <user> <msg> - Send direct message")
        self.client._add_message("/channels - List all channels")
        self.client._add_message("/users - List online users with status")
        self.client._add_message("/status <online|away|busy|dnd> [msg] - Set your status")
        self.client._add_message("/whois <user> - View user info")
        self.client._add_message("/react <msg_id> <emoji> - React to message (👍 ❤️ 😂 🎉)")
        self.client._add_message("/unreact <msg_id> <emoji> - Remove reaction")
        self.client._add_message("/reply <msg_id> <msg> - Reply in thread")
        self.client._add_message("/thread <msg_id> - View thread replies")
        self.client._add_message("/notify - Toggle notifications on/off")
        self.client._add_message("/sound - Toggle notification sounds")
        self.client._add_message("/test - Test notification system")
        self.client._add_message("/quit - Exit")
        self.client._add_message("")
        self.client._add_message("=== Markdown Formatting ===")
        self.client._add_message("**bold text** - Bold")
        self.client._add_message("*italic text* - Italic (underlined)")
        self.client._add_message("`code snippet` - Code (inverted)")
        self.client._add_message("@username - Mention (highlighted)")
        self.client._add_message("===============")
        self.client._add_message("")
        
        # Show notification status
        if hasattr(self.client, 'notifications') and self.client.notifications.enabled:
            self.client._add_message(f"*** Desktop notifications: enabled ({self.client.notifications.method}) ***")
        else:
            self.client._add_message("*** Desktop notifications: not available on this system ***")
        self.client._add_message("")
        
        self.draw(stdscr)
        
        import time
        last_typing_check = time.time()
        last_typing_users_count = 0
        
        while self.client.running:
            with self.client.messages_lock:
                current_message_count = len(self.client.messages)
            
            # Force redraw if typing users changed
            typing_users_count = len(self.client.typing_users)
            if typing_users_count != last_typing_users_count:
                self.needs_redraw = True
                last_typing_users_count = typing_users_count
            
            if current_message_count != self.last_message_count:
                self.last_message_count = current_message_count
                self.needs_redraw = True
            
            # Check if we should stop typing indicator (3 seconds of no typing)
            current_time = time.time()
            if self.client.is_typing and (current_time - self.client.last_keypress) > 3:
                self.client.is_typing = False
                self.client.send_message("__TYPING_STOP__")
            
            # Always redraw if there are typing users (to keep it visible)
            if typing_users_count > 0:
                if (current_time - last_typing_check) > 0.3:
                    self.needs_redraw = True
                    last_typing_check = current_time
            
            if self.needs_redraw:
                self.draw(stdscr)
                self.needs_redraw = False
            
            try:
                key = stdscr.getch()
            except KeyboardInterrupt:
                break
            
            if key == -1:
                continue
            
            if not self.handle_input(key):
                break
        
        # Clean up typing indicator
        if self.client.is_typing:
            self.client.send_message("__TYPING_STOP__")
        
        self.client.disconnect()


def get_server_info():
    """Prompt user for server connection details."""
    print("=== Chat Client - DMs & Channels ===")
    host = input("Server IP address (default: localhost): ").strip()
    if not host:
        host = "localhost"
    
    port_input = input("Server port (default: 5050): ").strip()
    try:
        port = int(port_input) if port_input else 5050
    except ValueError:
        print("Invalid port, using default 5050")
        port = 5050
    
    return host, port


def main():
    """Main entry point."""
    try:
        host, port = get_server_info()
        
        print(f"\nConnecting to {host}:{port}...")
        client = ChatClient(host, port)
        
        if not client.connect():
            print(f"Failed to connect to {host}:{port}")
            print("Please check the server address and ensure the server is running.")
            sys.exit(1)
        
        print("Connected! Starting authentication...")
        
        listener = threading.Thread(target=client.listen_to_server, daemon=True)
        listener.start()
        
        def auth_wrapper(stdscr):
            auth_ui = AuthUI(client)
            return auth_ui.run(stdscr)
        
        authenticated = curses.wrapper(auth_wrapper)
        
        if not authenticated or not client.running:
            print("\n*** Authentication cancelled or failed ***")
            client.disconnect()
            sys.exit(0)
        
        chat_ui = ChatUI(client)
        curses.wrapper(chat_ui.run)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        curses.endwin()
        print("\n*** Disconnected ***")


if __name__ == "__main__":
    main()
