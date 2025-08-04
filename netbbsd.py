#!/usr/bin/env python3
"""
## License

This project is licensed under the 3-clause BSD license. See the LICENSE file for details.

netbbsd.py - A modern take on traditional Bulletin Board Systems (BBSes).


This script implements an expandable BBS service designed to run on NetBSD or
any other Unix‑like operating system with Python 3. It includes telnet
support, optional SSH support via AsyncSSH, message boards, file areas,
multi‑user chat, a wall for leaving messages, door games, and a SysOp
administration console. Posts on message boards can include attachments up
to 20 MiB. Data is stored in SQLite by default, with optional password
hashing via bcrypt or PBKDF2.

## Quick start for new SysOps

1. **Run the server:** Execute this script with `python3 netbbs.py`. On first
   run it creates `netbbsd.ini` and a new SQLite database (`netbbsd.db`) in
   the current directory.

2. **Edit the configuration:** Open `netbbsd.ini` in a text editor. At a
   minimum set `hostname` in the `[general]` section to your public
   hostname or IP. Review other sections for security settings,
   registration questions, default user levels, and link configuration.

3. **Set up users and boards:** Connect via telnet (default port 2323) and
   create a SysOp account. Use the SysOp console (option 8 in the main
   menu) to create message boards and file areas, define user levels,
   registration questions, and manage preferences.

4. **Optional SSH support:** To allow SSH logins, install the `asyncssh`
   library on your system (`pkgin install py39-asyncssh` on NetBSD or
   `pip install asyncssh` on Linux). Enable SSH in `[general]` by
   setting `enable_ssh = true` and adjust `ssh_port` if needed. Restart
   NetBBSD and it will attempt to start an SSH server. Without `asyncssh`
   installed, SSH will remain disabled and a warning will be logged.

5. **Networking with other BBSes:** To link boards, channels, or file
   areas with other NetBBSD installations, edit `[link_hosts]` to map
   host aliases to URLs (including the peer’s `link_port`), then add
   entries in `[link_boards]`, `[link_channels]`, or `[link_areas]` to
   specify which boards/channels/areas should sync to which hosts. For
   security, add shared secrets under `[link_keys]` and set up
   corresponding keys on the peer systems.

6. **Review security settings:** The `[security]` section controls login
   throttling, password complexity, and other hardening options. Adjust
   these values to suit your environment.

7. **Explore and extend:** Use the SysOp console to configure user
   preferences, board permissions, moderators, and remote linking. The
   system is designed to be extended—feel free to dive into the code and
   add new features.

By default the server listens for telnet connections on port 2323 and
remote link messages on port 8686. Ports and other defaults can be
customized in the configuration file.

Author: Thiesi
"""

import asyncio
import hashlib
import os
import sqlite3
import sys
import time
import json
import urllib.request
import urllib.error
import logging
import configparser
import shutil
import re
import http.server
import socketserver
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import hmac
try:
    # Python 3.9+ has zoneinfo for timezone conversions
    from zoneinfo import ZoneInfo  # type: ignore
except Exception:
    ZoneInfo = None  # fallback if unavailable

try:
    import bcrypt  # type: ignore
    HAVE_BCRYPT = True
except ImportError:
    HAVE_BCRYPT = False

# Try to import AsyncSSH for optional SSH support. If not installed,
# HAVE_ASYNCSSH will be False and SSH functionality will be disabled.
try:
    import asyncssh  # type: ignore
    HAVE_ASYNCSSH = True
except Exception:
    HAVE_ASYNCSSH = False

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def hmac_compare(a: str, b: str) -> bool:
    """
    Compare two HMAC signatures in constant time to avoid timing attacks.
    Falls back to simple equality if compare_digest is unavailable.
    """
    try:
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    except Exception:
        return a == b

# ---------------------------------------------------------------------------
# Version information
# ---------------------------------------------------------------------------

# Current version of the NetBBSD software. This should be bumped whenever
# releasing a new version. The update checker compares this version to the
# remote version and will notify the SysOp if an update is available.
__version__ = "0.1.0"


###############################################################################
# Configuration file handling
###############################################################################

def load_config(path: str) -> configparser.ConfigParser:
    """Load the configuration from the given INI file.

    If the file does not exist, a default configuration will be written
    automatically. The configuration is stored in a global variable CONFIG.
    """
    cfg = configparser.ConfigParser()
    if os.path.exists(path):
        cfg.read(path)
    else:
        # Populate defaults
        cfg['general'] = {
            'motd': 'Welcome to NetBBSD! This is the default message of the day. Edit netbbsd.ini to change this.',
            # Hostname used for inter‑BBS communication; set to your BBS domain or IP
            'hostname': 'localhost',
            # Port on which this BBS listens for incoming NetBBSD Link requests.
            # Remote peers will send JSON payloads to this port for board
            # synchronization, chat linking, private messages, and control
            # commands. Choose a port that is open and reachable. The default
            # is 8686. Change this value if it conflicts with other services.
            'link_port': '8686',
            # Whether this node should act as the master for the entire NetBBSD Link. A
            # master node is trusted to issue link‑wide control commands (such as
            # deleting boards) that peer systems will honour without further
            # authentication. Only set this to 'true' on one node in your mesh.
            'is_master': 'false',
            # Enable SSH server if AsyncSSH is installed. When true, NetBBSD
            # will listen on the configured ssh_port for SSH connections.
            # SysOps can toggle this value in the configuration. Even if
            # AsyncSSH is not installed, setting this to true will cause
            # NetBBSD to attempt to start the SSH server and log an error if
            # the module is missing.
            'enable_ssh': 'false',
            # Port on which the SSH server will listen. Default is 2222.
            'ssh_port': '2222',
        }
        cfg['prompts'] = {
            'username': "Username (or 'quit' to exit): ",
            'password': 'Password: ',
            'create_account_confirm': "User '{username}' not found. Create new account? (y/n): ",
            'create_password': 'Create password: ',
            'login_invalid_password': 'Invalid password.',
            'login_too_many': 'Too many failed login attempts. Goodbye!',
            'create_account_success': 'Account created successfully!',
            'welcome_back': 'Welcome back, {username}!',
            'use_ansi': 'Do you want to enable ANSI colors? (y/n): ',
            'logoff_wall': 'Would you like to leave a wall message before logging off? (y/n): ',
        }
        cfg['menus'] = {
            'main_title': 'Main Menu',
            # Note: numbering of options matters; update when adding new menu items
            'main_options': '1) Message Boards\n2) File Areas\n3) Chat Room\n4) Wall\n5) Private Messages\n6) Door Games\n7) User Settings\n0) Log Off',
            'sysop_option': '8) SysOp Console',
            'boards_title': 'Message Boards',
            'file_areas_title': 'File Areas',
            'chat_enter': "Entering chat room. Type '/quit' to exit.",
            'chat_exit': 'Leaving chat room.',
        }
        # User level definitions: number = label
        cfg['levels'] = {
            '255': 'SysOp',
            '10': 'Regular',
            '0': 'Guest',
        }
        # Registration questions: key = field name, value = prompt text
        cfg['questions'] = {
            'real_name': 'Real Name',
            'country': 'Country',
            'city': 'City/Town/Village',
            'email': 'Email address',
            'dob': 'Date of Birth',
        }
        # By default all questions are editable by users
        cfg['questions_editable'] = {
            'real_name': 'true',
            'country': 'true',
            'city': 'true',
            'email': 'true',
            'dob': 'true',
        }
        # Question types and formats; default type is text
        cfg['question_types'] = {
            'dob': 'date',
        }
        cfg['question_formats'] = {
            'dob': '%Y-%m-%d',
        }
        # Defaults for global settings
        cfg['defaults'] = {
            'timezone': 'UTC',
            'time_format': '24h',
            'cols': '80',
            'rows': '24',
            'language': 'en',
            'sysop_pm_access': 'true',
            'chat_history_lines': '20',
            # Idle session timeout in seconds. Sessions with no input for this
            # duration will be disconnected automatically. The default is 600
            # seconds (10 minutes).
            'idle_timeout': '600',
        }
        # Remote hosts for inter‑BBS linking (empty by default). Keys are hostnames,
        # values are base URLs (e.g. https://remote.example.com/api). When you
        # configure link boards or remote private messaging, add entries here.
        cfg['link_hosts'] = {}
        # Link boards: maps local board names to comma‑separated hostnames of
        # remote BBSes that should receive posts from the board. Empty by default.
        cfg['link_boards'] = {}
        # Link areas: maps local file area names to comma‑separated hostnames
        # of remote BBSes that should receive uploaded files from
        # this area. Use this to build "NetBBSD Link Areas" for sharing
        # files across nodes. Empty by default.
        cfg['link_areas'] = {}
        # Link channels: maps local channel names (e.g. #general) to comma‑separated
        # hostnames of remote BBSes that should receive chat messages. Empty by default.
        cfg['link_channels'] = {}
        # Remote settings: control retry behaviour and notification for failed
        # outbound operations. These defaults can be tuned via SysOp menu.
        cfg['remote'] = {
            'retry_interval': '60',
            'max_attempts': '3',
            'notify_on_failure': 'true'
        }
        # File area settings
        cfg['file_areas'] = {
            # Default maximum file size in bytes for uploads. 0 means unlimited.
            # This limit applies to both local uploads and remote transfers.
            'max_file_size': '0'
        }
        # Security settings: login throttling and password policies
        cfg['security'] = {
            # Maximum failed login attempts within window
            'max_failed_attempts': '5',
            # Window length in seconds for failed attempts counting
            'fail_window': '60',
            # Block duration in seconds after threshold exceeded
            'block_duration': '60',
            # Password complexity: none, simple, medium, strong
            'password_complexity': 'none'
            ,
            # Bootstrap secret used to authenticate initial handshake messages
            # between NetBBSD nodes. Set this to the same value on both
            # hosts when linking for the first time. If left empty, a
            # random secret will be generated on first run and written
            # back to the configuration file. This secret is only used
            # for the handshake; per‑host secrets are exchanged and
            # stored separately.
            'bootstrap_secret': ''
        }
        # Link keys: shared secrets used to sign control messages per host.
        # For each host in link_hosts, you can specify a secret used for
        # HMAC signatures of remote payloads. Example:
        # myremote = supersecretkey
        cfg['link_keys'] = {}
        # Hosts that are currently considered down. Each key is a host alias from
        # the [link_hosts] section and the value is an ISO timestamp indicating
        # when the downtime expires. If the value is empty or missing a
        # timestamp, the downtime is treated as indefinite. The remote queue
        # worker skips sending tasks to hosts listed here until the expiry
        # passes. SysOps can manage this section via the configuration menu.
        cfg['link_down'] = {}
        # Hosts that are temporarily down. Specify hostnames as keys. If a
        # host appears here, no outbound messages will be sent and tasks
        # will remain queued until you remove the host from this section.
        cfg['link_down'] = {}
        # Logging settings: configure log level and optional log file. Level can be
        # debug, info, warning, error. If a log file is specified, logs are
        # written there; otherwise they go to stderr. See logging.basicConfig.
        cfg['logging'] = {
            'level': 'info',
            'file': ''
        }
        # Update settings: specify URLs for version check and download
        cfg['update'] = {
            'check_url': 'https://example.com/netbbsd/version.json',
            'download_url': 'https://example.com/netbbsd/netbbsd.py'
        }

        # Maintenance settings: configure automatic cleanup of posts and files.
        # interval: how often maintenance runs, in hours. grace_period: how
        # many days an expired item is retained before permanent deletion.
        cfg['maintenance'] = {
            'interval': '24',
            'grace_period': '7'
        }
        # If bootstrap_secret is empty, generate a new random secret for
        # initial handshake authentication. The secret will be written
        # into the configuration file. Use 32 bytes of randomness
        # encoded as hex for sufficient entropy.
        bs = cfg['security'].get('bootstrap_secret', '')
        if not bs:
            try:
                import secrets  # standard library
                cfg['security']['bootstrap_secret'] = secrets.token_hex(32)
            except Exception:
                # Fallback to os.urandom if secrets unavailable
                cfg['security']['bootstrap_secret'] = os.urandom(32).hex()
        with open(path, 'w') as f:
            cfg.write(f)
    return cfg


###############################################################################
# Configuration
###############################################################################

HOST = '0.0.0.0'
TELNET_PORT = 2323
SSH_PORT: Optional[int] = None  # Example: 2222

# Path to the SQLite database. For NetBSD packaging you might relocate this
# under /var or /usr/pkg/etc depending on your deployment. During development
# this will live in the working directory.
DB_PATH = os.environ.get('NETBBSD_DB', 'netbbsd.db')

# Path to the configuration file. This INI file defines prompts, menus and
# other user‑visible text. If it does not exist, sensible defaults will be
# written automatically on startup. You can edit the file with any text
# editor such as nano or vi.
CONFIG_PATH = os.environ.get('NETBBSD_CONFIG', 'netbbsd.ini')

# Control whether password hashing is used. If set to False, passwords will be
# stored in clear text. This is strongly discouraged for production use.
USE_HASHED_PASSWORDS = True

# Default ANSI color codes. These may be stripped at run time if the user
# elects not to use ANSI. Colors can be customized in the configuration file
# (though the codes themselves are not configurable to avoid injection of
# arbitrary escape sequences).
ANSI_RESET = '\x1b[0m'
ANSI_BOLD = '\x1b[1m'
ANSI_RED = '\x1b[31m'
ANSI_GREEN = '\x1b[32m'
ANSI_YELLOW = '\x1b[33m'
ANSI_BLUE = '\x1b[34m'
ANSI_MAGENTA = '\x1b[35m'
ANSI_CYAN = '\x1b[36m'
ANSI_WHITE = '\x1b[37m'

# Regular expression to match ANSI escape sequences. Used to strip
# control sequences from user-provided content.
ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

# Allowed username pattern: letters, digits, underscores, and hyphens, 3-20 chars
USERNAME_RE = re.compile(r'^[A-Za-z0-9_-]{3,20}$')


def sanitize_text(text: str) -> str:
    """Remove ANSI escape codes and control characters from text."""
    # Strip ANSI escape sequences
    text = ANSI_ESCAPE_RE.sub('', text)
    # Remove other non-printable control characters (except newline and tab)
    cleaned = ''.join(ch for ch in text if (32 <= ord(ch) <= 126) or ch in ('\n', '\t'))
    return cleaned


# Telnet IAC and control sequence handling

def clean_telnet_input(raw: bytes) -> str:
    """Remove telnet control sequences (IAC negotiations) from raw input.

    Telnet clients may send negotiation commands beginning with the
    IAC (0xFF) byte. This function strips these commands so that user
    input is not polluted with control codes. It also decodes the
    resulting bytes into a UTF‑8 string, ignoring decoding errors.
    """
    out_bytes = bytearray()
    i = 0
    data = raw
    length = len(data)
    while i < length:
        byte = data[i]
        # IAC (Interpret As Command) initiates a control sequence. Skip it
        if byte == 0xFF:
            # IAC commands are at least two bytes. Some commands may be
            # three bytes (e.g. IAC DO <option>). We'll skip the next
            # two bytes if possible.
            if i + 2 < length:
                i += 3
            else:
                # Incomplete sequence; stop processing
                break
            continue
        # Otherwise copy byte if printable or whitespace
        out_bytes.append(byte)
        i += 1
    # Decode to string
    try:
        return out_bytes.decode('utf-8', 'ignore')
    except Exception:
        return ''


def validate_password(password: str, complexity: str) -> bool:
    """Validate password based on complexity level.

    Complexity levels:
    - none: any password accepted
    - simple: minimum 6 characters
    - medium: minimum 8 characters and at least one digit
    - strong: minimum 12 characters and at least one lowercase, uppercase, digit and special character
    """
    if complexity == 'none' or not complexity:
        return True
    if complexity == 'simple':
        return len(password) >= 6
    if complexity == 'medium':
        if len(password) < 8:
            return False
        if not any(ch.isdigit() for ch in password):
            return False
        return True
    if complexity == 'strong':
        if len(password) < 12:
            return False
        if not any(ch.islower() for ch in password):
            return False
        if not any(ch.isupper() for ch in password):
            return False
        if not any(ch.isdigit() for ch in password):
            return False
        if not any(ch in '!@#$%^&*()-_=+[{]}\\|;:\",<.>/?' for ch in password):
            return False
        return True
    # Unknown level defaults to True
    return True


def valid_username(name: str) -> bool:
    """Check if the username matches a safe pattern."""
    return bool(USERNAME_RE.match(name))

# Global configuration dictionary loaded from CONFIG_PATH. Populated by
# load_config().
CONFIG: Optional[configparser.ConfigParser] = None

# Directory where ANSI menu graphics are stored. If a file matching a menu name
# (e.g. 'main_menu.ans') exists in this directory, its contents will be sent
# instead of the text‑based menu. This allows SysOps to create colorful
# full‑screen ANSI menus using art packages such as TheDraw or PabloDraw. By
# default this directory is 'menus' relative to the working directory.
MENU_DIR = os.environ.get('NETBBSD_MENU_DIR', 'menus')


###############################################################################
# Database handling
###############################################################################

class Database:
    """Simple wrapper around SQLite for storing users, boards, messages and more."""

    def __init__(self, db_path: str) -> None:
        self.conn = sqlite3.connect(db_path)
        # Return rows as dictionaries
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    # Current schema version. Increment this whenever the database schema
    # changes (e.g. new tables or columns). The version is stored in the
    # SQLite user_version pragma. When init_schema() runs, it will upgrade
    # older schemas to the current version.
    # Bump this whenever the database schema changes. Incremental upgrades
    # should be handled in init_schema().
    #
    # Version history:
    #   4 – added ``max_size`` column on the file_boards table to support
    #       file area maximum sizes.
    #   5 – renamed file_boards table to file_areas and updated references.
    #       Added attachments table for message board posts.
    # Current version 6 adds a ``max_age`` column to the ``file_areas`` table
    # for maintenance of file uploads. When upgrading from version 5 or
    # earlier, init_schema() will add the column. See init_schema() for
    # incremental upgrade logic.
    # Version 8 adds the link_keys table to store per‑host shared secrets and
    # moves secret management from the configuration into the database. If
    # upgrading from an earlier version (<=7), init_schema() will create
    # the new table. When bumping this constant, ensure the corresponding
    # upgrade block is added below.
    SCHEMA_VERSION: int = 8

    def init_schema(self) -> None:
        """Initialize or upgrade the database schema.

        If the database is empty (user_version = 0), all tables are created
        afresh. If the schema version is lower than the current
        SCHEMA_VERSION, incremental upgrades can be applied here to modify
        existing tables or add new ones. After running, the user_version
        pragma is set to SCHEMA_VERSION.
        """
        cur = self.conn.cursor()
        # Get current schema version stored in the database
        cur.execute('PRAGMA user_version')
        row = cur.fetchone()
        current_version = row[0] if row else 0
        # If fresh database or version mismatch, create tables and perform upgrades
        if current_version == 0:
            # Fresh database: create all tables
            self._create_tables(cur)
            cur.execute(f'PRAGMA user_version = {self.SCHEMA_VERSION}')
            self.conn.commit()
            return

        # Perform incremental upgrades for existing databases. If you are
        # running with an empty database, these blocks will be skipped.
        if current_version < 4:
            # Version 4 added the max_size column on the legacy file_boards table.
            try:
                cur.execute('ALTER TABLE file_boards ADD COLUMN max_size INTEGER NOT NULL DEFAULT 0')
            except Exception:
                pass
            current_version = 4

        if current_version < 5:
            # Version 5 renames file_boards to file_areas and updates the
            # files table to reference file_areas. We perform a simple
            # migration: drop the old tables if they exist and recreate
            # them fresh. As this project has no existing production
            # deployments, preserving data is not necessary. This keeps
            # the upgrade simple and avoids complex ALTER TABLE statements.
            try:
                cur.execute('DROP TABLE IF EXISTS files')
            except Exception:
                pass
            try:
                cur.execute('DROP TABLE IF EXISTS file_boards')
            except Exception:
                pass
            # Recreate tables using the new schema
            self._create_tables(cur)
            current_version = 5

        # Version 6 adds max_age column to file_areas for retention
        if current_version < 6:
            try:
                cur.execute('ALTER TABLE file_areas ADD COLUMN max_age INTEGER NOT NULL DEFAULT 0')
            except Exception:
                # The column may already exist if the upgrade was applied
                # partially. Ignore errors here.
                pass
            current_version = 6

        # Version 7 adds the link_keys table. This table stores per-host
        # shared secrets that were previously configured in the INI file. If
        # the table does not exist, create it. We don't migrate any
        # existing [link_keys] configuration entries here; these will be
        # inserted into the table at runtime when first used.
        if current_version < 7:
            try:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS link_keys (
                        host TEXT PRIMARY KEY,
                        secret TEXT NOT NULL
                    )
                ''')
            except Exception:
                pass
            current_version = 7

        # Version 8 bumps the schema version to recognize the link_keys
        # addition. No schema changes are needed beyond this point. Future
        # upgrades should add new blocks here.
        if current_version < 8:
            # Nothing to migrate for version 8; simply bump the version.
            current_version = 8

        # Set user_version to current SCHEMA_VERSION
        cur.execute(f'PRAGMA user_version = {self.SCHEMA_VERSION}')
        self.conn.commit()

    def _create_tables(self, cur: sqlite3.Cursor) -> None:
        """Create all database tables for a new database."""
        # Users
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                level INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        ''')
        # Message boards
        cur.execute('''
            CREATE TABLE IF NOT EXISTS boards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                min_level INTEGER NOT NULL DEFAULT 0,
                min_age INTEGER NOT NULL DEFAULT 0,
                moderated INTEGER NOT NULL DEFAULT 0,
                -- Maximum age of posts (in days). 0 means retain indefinitely.
                max_age INTEGER NOT NULL DEFAULT 0
            )
        ''')
        # Threads (topics) in message boards
        cur.execute('''
            CREATE TABLE IF NOT EXISTS threads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                board_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(board_id) REFERENCES boards(id),
                FOREIGN KEY(author_id) REFERENCES users(id)
            )
        ''')
        # Individual posts/messages in threads with moderation flag
        cur.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                content TEXT NOT NULL,
                approved INTEGER NOT NULL DEFAULT 1,
                -- Pinned posts are displayed above others and are not
                -- automatically expired or deleted.
                pinned INTEGER NOT NULL DEFAULT 0,
                -- Exempt posts are not subject to expiration or deletion.
                exempt INTEGER NOT NULL DEFAULT 0,
                -- Timestamp when the post was marked expired. Null means not expired.
                expired_at TEXT,
                FOREIGN KEY(thread_id) REFERENCES threads(id),
                FOREIGN KEY(author_id) REFERENCES users(id)
            )
        ''')
        # File areas. Formerly named file_boards. ``max_size`` is the
        # maximum allowed file size in bytes (0 means unlimited). ``moderated``
        # indicates whether uploads require approval. The table is called
        # ``file_areas`` to match the new naming convention. It replaces
        # the old ``file_boards`` table.
        cur.execute('''
            CREATE TABLE IF NOT EXISTS file_areas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                min_level INTEGER NOT NULL DEFAULT 0,
                min_age INTEGER NOT NULL DEFAULT 0,
                moderated INTEGER NOT NULL DEFAULT 0,
                max_size INTEGER NOT NULL DEFAULT 0,
                -- Maximum age of files in this area (in days). 0 means
                -- retain indefinitely. This supports automatic expiration
                -- of old uploads during maintenance.
                max_age INTEGER NOT NULL DEFAULT 0
            )
        ''')
        # Files stored in file areas
        cur.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                board_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                uploader_id INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                size INTEGER NOT NULL,
                path TEXT NOT NULL,
                -- Pinned files remain at the top of listings and are not auto expired.
                pinned INTEGER NOT NULL DEFAULT 0,
                -- Exempt files are excluded from automatic expiration/deletion.
                exempt INTEGER NOT NULL DEFAULT 0,
                -- When the file was marked expired.
                expired_at TEXT,
                FOREIGN KEY(board_id) REFERENCES file_areas(id),
                FOREIGN KEY(uploader_id) REFERENCES users(id)
            )
        ''')
        # Wall messages
        cur.execute('''
            CREATE TABLE IF NOT EXISTS wall (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user_id INTEGER NOT NULL,
                to_user_id INTEGER,
                created_at TEXT NOT NULL,
                content TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(from_user_id) REFERENCES users(id),
                FOREIGN KEY(to_user_id) REFERENCES users(id)
            )
        ''')
        # Board access overrides
        cur.execute('''
            CREATE TABLE IF NOT EXISTS board_access (
                board_type TEXT NOT NULL,
                board_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (board_type, board_id, user_id)
            )
        ''')
        # User profiles
        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id INTEGER NOT NULL,
                field TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (user_id, field),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Private messages
        cur.execute('''
            CREATE TABLE IF NOT EXISTS private_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user_id INTEGER NOT NULL,
                to_user_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                receipt_visible INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(from_user_id) REFERENCES users(id),
                FOREIGN KEY(to_user_id) REFERENCES users(id)
            )
        ''')
        # User preferences
        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (user_id, key),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Chat history
        cur.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                nickname TEXT NOT NULL,
                created_at TEXT NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Channels
        cur.execute('''
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                min_level INTEGER NOT NULL DEFAULT 0,
                min_age INTEGER NOT NULL DEFAULT 0,
                link INTEGER NOT NULL DEFAULT 0
            )
        ''')
        # Channel access overrides
        cur.execute('''
            CREATE TABLE IF NOT EXISTS channel_access (
                channel_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY(channel_id) REFERENCES channels(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Moderators
        cur.execute('''
            CREATE TABLE IF NOT EXISTS moderators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                perms TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Chat sanctions
        cur.execute('''
            CREATE TABLE IF NOT EXISTS chat_sanctions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                channel_id INTEGER,
                action TEXT NOT NULL,
                expires_at TEXT,
                set_by INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(channel_id) REFERENCES channels(id),
                FOREIGN KEY(set_by) REFERENCES users(id)
            )
        ''')
        # Remote queue
        cur.execute('''
            CREATE TABLE IF NOT EXISTS remote_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                op_type TEXT NOT NULL,
                host TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                payload TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                last_attempt TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
            )
        ''')
        # Remote thread map: maps (from_host, remote_thread_id) to local thread id
        # This table is used to correlate remote thread identifiers with
        # locally created thread IDs. When a thread is synchronized from a
        # remote host we insert a row mapping the remote thread ID to the
        # newly created local thread. Subsequent posts referring to the
        # remote thread ID can then be routed to the correct local thread.
        cur.execute('''
            CREATE TABLE IF NOT EXISTS remote_thread_map (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_host TEXT NOT NULL,
                remote_thread_id TEXT NOT NULL,
                local_thread_id INTEGER NOT NULL,
                UNIQUE(from_host, remote_thread_id)
            )
        ''')
        # Moderation log
        cur.execute('''
            CREATE TABLE IF NOT EXISTS moderation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                moderator_id INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                action TEXT NOT NULL,
                info TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(moderator_id) REFERENCES users(id)
            )
        ''')

        # Link keys: store per‑host shared secrets used for HMAC signing and
        # verification of remote messages. Each entry associates a host alias
        # with a secret value. A secret for the local host is also stored
        # here and used when sending our secret to peers. See the handshake
        # implementation for details.
        cur.execute('''
            CREATE TABLE IF NOT EXISTS link_keys (
                host TEXT PRIMARY KEY,
                secret TEXT NOT NULL
            )
        ''')

        # Attachments for posts on message boards. Each attachment belongs
        # to a specific post (thread message) and is stored on disk. The
        # ``path`` column stores the relative file system path where the
        # attachment is saved. ``size`` is the file size in bytes.
        cur.execute('''
            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY(post_id) REFERENCES posts(id)
            )
        ''')
        

        # Create user_preferences table for storing per-user settings
        cur.execute('''
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (user_id, key),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        self.conn.commit()

        # Create chat_messages table to persist chat history
        cur.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                nickname TEXT NOT NULL,
                created_at TEXT NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        self.conn.commit()

        # Channels table: stores chat channels and their restrictions
        cur.execute('''
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                min_level INTEGER NOT NULL DEFAULT 0,
                min_age INTEGER NOT NULL DEFAULT 0,
                link INTEGER NOT NULL DEFAULT 0
            )
        ''')
        # Channel access overrides: grant access to users regardless of level/age
        cur.execute('''
            CREATE TABLE IF NOT EXISTS channel_access (
                channel_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY(channel_id) REFERENCES channels(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Moderators: assign moderation permissions to users for boards, files, channels or globally
        cur.execute('''
            CREATE TABLE IF NOT EXISTS moderators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                perms TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Chat sanctions: mutes and bans with expiration
        cur.execute('''
            CREATE TABLE IF NOT EXISTS chat_sanctions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                channel_id INTEGER,
                action TEXT NOT NULL,
                expires_at TEXT,
                set_by INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(channel_id) REFERENCES channels(id),
                FOREIGN KEY(set_by) REFERENCES users(id)
            )
        ''')
        # Remote queue: pending remote operations for boards, PMs, channels
        cur.execute('''
            CREATE TABLE IF NOT EXISTS remote_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                op_type TEXT NOT NULL,
                host TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                payload TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                last_attempt TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
            )
        ''')
        # Moderation logs
        cur.execute('''
            CREATE TABLE IF NOT EXISTS moderation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                moderator_id INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER,
                action TEXT NOT NULL,
                info TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(moderator_id) REFERENCES users(id)
            )
        ''')
        self.conn.commit()

    # User operations
    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        return cur.fetchone()

    def add_user(self, username: str, password: str, level: int = 0) -> int:
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO users (username, password, level, created_at) VALUES (?, ?, ?, ?)',
            (username, password, level, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_last_login(self, user_id: int) -> None:
        now = datetime.utcnow().isoformat()
        self.conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (now, user_id))
        self.conn.commit()

    # Board operations
    def list_boards(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM boards')
        return cur.fetchall()

    def list_file_areas(self) -> List[sqlite3.Row]:
        """Return a list of all file areas.

        The underlying table is ``file_areas``. Each returned row
        includes ``min_level``, ``min_age`` and ``max_size``.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM file_areas')
        return cur.fetchall()

    def get_post_flags(self, post_id: int) -> tuple:
        """Return the pinned and exempt flags for a given post.

        Returns a tuple (pinned, exempt) where each value is 0 or 1.
        If the post does not exist, returns (0, 0).
        """
        cur = self.conn.cursor()
        cur.execute('SELECT pinned, exempt FROM posts WHERE id = ?', (post_id,))
        row = cur.fetchone()
        if row:
            return (row['pinned'], row['exempt'])
        return (0, 0)

    # -----------------------------------------------------------------
    # Maintenance support
    #
    def get_boards_with_max_age(self) -> List[sqlite3.Row]:
        """Return boards with a positive max_age (days > 0)."""
        cur = self.conn.cursor()
        cur.execute('SELECT id, max_age FROM boards WHERE max_age > 0')
        return cur.fetchall()

    def get_file_areas_with_max_age(self) -> List[sqlite3.Row]:
        """Return file areas with a positive max_age (days > 0)."""
        cur = self.conn.cursor()
        cur.execute('SELECT id, max_age FROM file_areas WHERE max_age > 0')
        return cur.fetchall()

    def expire_posts(self, board_id: int, cutoff: datetime) -> None:
        """Mark posts in the given board older than cutoff as expired.

        Only posts that are not pinned, not exempt, and not already expired
        are affected. The posts table's expired_at column is set to the
        ISO timestamp of the current time.
        """
        ts = cutoff.isoformat()
        cur = self.conn.cursor()
        cur.execute(
            '''
            UPDATE posts SET expired_at = ?
            WHERE id IN (
                SELECT posts.id
                FROM posts
                JOIN threads ON posts.thread_id = threads.id
                WHERE threads.board_id = ?
                  AND posts.pinned = 0
                  AND posts.exempt = 0
                  AND posts.expired_at IS NULL
                  AND posts.created_at < ?
            )
            ''',
            (ts, board_id, ts)
        )
        self.conn.commit()

    def delete_expired_posts(self, delete_before: datetime) -> None:
        """Permanently remove posts marked expired before the given timestamp.

        This also deletes any attachments associated with the posts and
        cleans up the attachments table.
        """
        cutoff = delete_before.isoformat()
        cur = self.conn.cursor()
        # Select posts eligible for deletion
        cur.execute(
            '''
            SELECT posts.id
            FROM posts
            WHERE posts.expired_at IS NOT NULL
              AND posts.expired_at < ?
              AND posts.pinned = 0
              AND posts.exempt = 0
            ''',
            (cutoff,)
        )
        rows = cur.fetchall()
        post_ids = [row['id'] for row in rows]
        if not post_ids:
            return
        # Delete attachments and their files
        for post_id in post_ids:
            atts = self.list_attachments(post_id)
            for att in atts:
                path = att['path']
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
                # Remove from attachments table
                cur.execute('DELETE FROM attachments WHERE id = ?', (att['id'],))
        # Delete posts
        cur.executemany('DELETE FROM posts WHERE id = ?', [(pid,) for pid in post_ids])
        self.conn.commit()

    def expire_files(self, area_id: int, cutoff: datetime) -> None:
        """Mark files in the given file area older than cutoff as expired."""
        ts = cutoff.isoformat()
        cur = self.conn.cursor()
        cur.execute(
            '''
            UPDATE files SET expired_at = ?
            WHERE board_id = ?
              AND pinned = 0
              AND exempt = 0
              AND expired_at IS NULL
              AND uploaded_at < ?
            ''',
            (ts, area_id, ts)
        )
        self.conn.commit()

    def delete_expired_files(self, delete_before: datetime) -> None:
        """Permanently remove files marked expired before delete_before."""
        cutoff = delete_before.isoformat()
        cur = self.conn.cursor()
        cur.execute(
            '''
            SELECT id, path
            FROM files
            WHERE expired_at IS NOT NULL
              AND expired_at < ?
              AND pinned = 0
              AND exempt = 0
            ''',
            (cutoff,)
        )
        rows = cur.fetchall()
        if not rows:
            return
        for row in rows:
            file_id = row['id']
            path = row['path']
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            cur.execute('DELETE FROM files WHERE id = ?', (file_id,))
        self.conn.commit()

    def user_can_access_board(self, board_type: str, board_id: int, user: Optional['User']) -> bool:
        """Determine if a user may access a board of the given type.

        board_type should be 'msg' for message boards or 'file' for file boards.
        A user can access a board if their level is greater than or equal to the
        board's min_level, or if an explicit override entry exists in the
        board_access table.
        """
        if user is None:
            return False
        cur = self.conn.cursor()
        if board_type == 'msg':
            cur.execute('SELECT min_level, min_age FROM boards WHERE id = ?', (board_id,))
        else:
            # For file areas
            cur.execute('SELECT min_level, min_age FROM file_areas WHERE id = ?', (board_id,))
        row = cur.fetchone()
        if not row:
            return False
        min_level = row['min_level']
        min_age = row['min_age'] if 'min_age' in row.keys() else 0
        # Age check
        if min_age and min_age > 0:
            age = self.get_user_age(user.id)
            if age is None or age < min_age:
                # Age not provided or less than required
                return False
        if user.level >= min_level:
            return True
        # Check override
        cur.execute('SELECT 1 FROM board_access WHERE board_type = ? AND board_id = ? AND user_id = ?', (board_type, board_id, user.id))
        return cur.fetchone() is not None

    def grant_board_access(self, board_type: str, board_id: int, user_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT OR IGNORE INTO board_access (board_type, board_id, user_id) VALUES (?, ?, ?)', (board_type, board_id, user_id))
        self.conn.commit()

    def revoke_board_access(self, board_type: str, board_id: int, user_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute('DELETE FROM board_access WHERE board_type = ? AND board_id = ? AND user_id = ?', (board_type, board_id, user_id))
        self.conn.commit()

    # Attachment operations
    def add_attachment(self, post_id: int, filename: str, path: str, size: int) -> int:
        """Insert a new attachment record into the database.

        Returns the ID of the newly inserted attachment.
        """
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO attachments (post_id, filename, path, size, uploaded_at) VALUES (?, ?, ?, ?, ?)',
            (post_id, filename, path, size, now)
        )
        self.conn.commit()
        return cur.lastrowid

    def list_attachments(self, post_id: int) -> List[sqlite3.Row]:
        """Return all attachments for the given post."""
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM attachments WHERE post_id = ?', (post_id,))
        return cur.fetchall()

    def get_board(self, board_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM boards WHERE id = ?', (board_id,))
        return cur.fetchone()

    def add_board(self, name: str, description: str, min_level: int = 0) -> int:
        """Create a new message board with the given minimum user level."""
        cur = self.conn.cursor()
        cur.execute('INSERT INTO boards (name, description, min_level) VALUES (?, ?, ?)', (name, description, min_level))
        self.conn.commit()
        return cur.lastrowid

    def get_board_by_name(self, name: str) -> Optional[sqlite3.Row]:
        """Return a board row by its name or None if not found."""
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM boards WHERE name = ?', (name,))
        return cur.fetchone()

    # Thread and post operations
    def list_threads(self, board_id: int) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT threads.*, users.username AS author FROM threads JOIN users ON users.id = threads.author_id WHERE board_id = ? ORDER BY created_at DESC', (board_id,))
        return cur.fetchall()

    def add_thread(self, board_id: int, title: str, author_id: int) -> int:
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO threads (board_id, title, author_id, created_at) VALUES (?, ?, ?, ?)',
            (board_id, title, author_id, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_posts(self, thread_id: int) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        # Also fetch board moderation status to decide if unapproved posts should be hidden.
        # Determine board_id from thread
        cur.execute('SELECT board_id FROM threads WHERE id = ?', (thread_id,))
        board = cur.fetchone()
        moderated = 0
        if board:
            b_id = board['board_id']
            # Check message board
            cur.execute('SELECT moderated FROM boards WHERE id = ?', (b_id,))
            row = cur.fetchone()
            if row:
                moderated = row['moderated']
        # If board is moderated, only show approved posts
        if moderated:
            cur.execute('SELECT posts.*, users.username AS author FROM posts JOIN users ON users.id = posts.author_id WHERE thread_id = ? AND approved = 1 ORDER BY created_at', (thread_id,))
        else:
            cur.execute('SELECT posts.*, users.username AS author FROM posts JOIN users ON users.id = posts.author_id WHERE thread_id = ? ORDER BY created_at', (thread_id,))
        return cur.fetchall()

    def add_post(self, thread_id: int, author_id: int, content: str, approved: Optional[bool] = None) -> int:
        """Insert a new post. If approved is None, determine based on board moderation.

        When a board is moderated, posts from non‑moderators are inserted with approved=0 and require approval.
        """
        now = datetime.utcnow().isoformat()
        # Determine approval state if not provided
        if approved is None:
            # Determine board moderation
            cur = self.conn.cursor()
            cur.execute('SELECT board_id FROM threads WHERE id = ?', (thread_id,))
            row = cur.fetchone()
            board_id = row['board_id'] if row else None
            moderated = 0
            if board_id:
                cur.execute('SELECT moderated FROM boards WHERE id = ?', (board_id,))
                mrow = cur.fetchone()
                if mrow:
                    moderated = mrow['moderated']
            # If moderated: require approval (approved=0), else 1
            approved = 0 if moderated else 1
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO posts (thread_id, author_id, created_at, content, approved) VALUES (?, ?, ?, ?, ?)',
            (thread_id, author_id, now, content, 1 if approved else 0),
        )
        self.conn.commit()
        return cur.lastrowid

    # Wall operations
    def post_wall_message(self, from_user_id: int, to_user_id: Optional[int], content: str) -> int:
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO wall (from_user_id, to_user_id, created_at, content) VALUES (?, ?, ?, ?)',
            (from_user_id, to_user_id, now, content),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_wall_messages(self, user_id: Optional[int] = None) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        if user_id is None:
            cur.execute('SELECT wall.*, fu.username AS from_user, tu.username AS to_user FROM wall LEFT JOIN users fu ON fu.id = wall.from_user_id LEFT JOIN users tu ON tu.id = wall.to_user_id ORDER BY created_at DESC LIMIT 20')
        else:
            cur.execute('SELECT wall.*, fu.username AS from_user, tu.username AS to_user FROM wall LEFT JOIN users fu ON fu.id = wall.from_user_id LEFT JOIN users tu ON tu.id = wall.to_user_id WHERE to_user_id = ? OR to_user_id IS NULL ORDER BY created_at DESC LIMIT 20', (user_id,))
        return cur.fetchall()

    # SysOp: list users
    def list_users(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM users ORDER BY username')
        return cur.fetchall()

    def delete_user(self, user_id: int) -> None:
        self.conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        self.conn.commit()

    # User profile operations
    def set_user_profile(self, user_id: int, field: str, value: str) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT OR REPLACE INTO user_profiles (user_id, field, value) VALUES (?, ?, ?)', (user_id, field, value))
        self.conn.commit()

    def get_user_profile(self, user_id: int) -> Dict[str, str]:
        cur = self.conn.cursor()
        cur.execute('SELECT field, value FROM user_profiles WHERE user_id = ?', (user_id,))
        return {row['field']: row['value'] for row in cur.fetchall()}

    # Private message operations
    def add_private_message(self, from_user_id: int, to_user_id: int, subject: str, content: str, receipt_visible: bool = True) -> int:
        """Add a private message. If receipt_visible is False, the sender will not see whether it was read."""
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO private_messages (from_user_id, to_user_id, subject, content, created_at, receipt_visible) VALUES (?, ?, ?, ?, ?, ?)',
            (from_user_id, to_user_id, subject, content, now, 1 if receipt_visible else 0),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_private_messages(self, user_id: int) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT pm.*, u.username as from_user FROM private_messages pm JOIN users u ON u.id = pm.from_user_id WHERE pm.to_user_id = ? ORDER BY created_at DESC', (user_id,))
        return cur.fetchall()

    def list_sent_private_messages(self, user_id: int) -> List[sqlite3.Row]:
        """Return messages sent by the given user, including to_user username."""
        cur = self.conn.cursor()
        cur.execute('SELECT pm.*, u.username as to_user FROM private_messages pm JOIN users u ON u.id = pm.to_user_id WHERE pm.from_user_id = ? ORDER BY created_at DESC', (user_id,))
        return cur.fetchall()

    def list_all_private_messages(self) -> List[sqlite3.Row]:
        """Return all private messages for SysOp view, with from and to usernames."""
        cur = self.conn.cursor()
        cur.execute('''SELECT pm.*, uf.username AS from_user, ut.username AS to_user
                       FROM private_messages pm
                       JOIN users uf ON uf.id = pm.from_user_id
                       JOIN users ut ON ut.id = pm.to_user_id
                       ORDER BY created_at DESC''')
        return cur.fetchall()

    def update_private_message_receipt_visible(self, msg_id: int, visible: bool) -> None:
        """Set whether the sender of a message can see the read status (receipt)."""
        val = 1 if visible else 0
        self.conn.execute('UPDATE private_messages SET receipt_visible = ? WHERE id = ?', (val, msg_id))
        self.conn.commit()

    # User preference operations
    def set_user_preference(self, user_id: int, key: str, value: str) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT OR REPLACE INTO user_preferences (user_id, key, value) VALUES (?, ?, ?)', (user_id, key, value))
        self.conn.commit()

    def get_user_preference(self, user_id: int, key: str, default: Optional[str] = None) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM user_preferences WHERE user_id = ? AND key = ?', (user_id, key))
        row = cur.fetchone()
        if row:
            return row['value']
        return default

    def get_user_preferences(self, user_id: int) -> Dict[str, str]:
        cur = self.conn.cursor()
        cur.execute('SELECT key, value FROM user_preferences WHERE user_id = ?', (user_id,))
        return {row['key']: row['value'] for row in cur.fetchall()}

    # Signature operations using user_profiles table
    def get_user_signature(self, user_id: int) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM user_profiles WHERE user_id = ? AND field = ?', (user_id, 'signature'))
        row = cur.fetchone()
        return row['value'] if row else None

    def set_user_signature(self, user_id: int, text: str) -> None:
        self.set_user_profile(user_id, 'signature', text)

    # Chat message operations
    def add_chat_message(self, channel: str, user_id: int, nickname: str, content: str) -> int:
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute('INSERT INTO chat_messages (channel, user_id, nickname, created_at, content) VALUES (?, ?, ?, ?, ?)',
                    (channel, user_id, nickname, now, content))
        self.conn.commit()
        return cur.lastrowid

    def list_chat_messages(self, channel: str, limit: int = 20) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT cm.*, u.username FROM chat_messages cm JOIN users u ON u.id = cm.user_id WHERE channel = ? ORDER BY created_at DESC LIMIT ?', (channel, limit))
        return list(reversed(cur.fetchall()))  # return in chronological order

    # ------------------------------------------------------------------
    # Link key operations
    def get_link_secret(self, host: str) -> Optional[str]:
        """Return the shared secret for a given host alias or None if not set."""
        cur = self.conn.cursor()
        cur.execute('SELECT secret FROM link_keys WHERE host = ?', (host,))
        row = cur.fetchone()
        return row['secret'] if row else None

    def set_link_secret(self, host: str, secret: str) -> None:
        """Insert or update the shared secret for the given host alias."""
        cur = self.conn.cursor()
        # Upsert semantics: update if exists, otherwise insert
        cur.execute('INSERT INTO link_keys (host, secret) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET secret = excluded.secret',
                    (host, secret))
        self.conn.commit()

    def ensure_local_secret(self, host: str) -> str:
        """Ensure that a secret exists for the local host. If not, generate one.

        Returns the existing or newly generated secret. The local host alias
        should correspond to the value of CONFIG['general']['hostname'].
        """
        secret = self.get_link_secret(host)
        if secret:
            return secret
        # Generate a new random secret. Use secrets.token_hex for high entropy.
        try:
            import secrets as _secrets  # import locally to avoid global requirement
            secret = _secrets.token_hex(32)
        except Exception:
            # Fallback to os.urandom if secrets unavailable
            secret = os.urandom(32).hex()
        self.set_link_secret(host, secret)
        return secret

    # ------------------------------------------------------------------
    # Channel operations
    def get_channel(self, name: str) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM channels WHERE name = ?', (name,))
        return cur.fetchone()

    def add_channel(self, name: str, description: str = '', min_level: int = 0, min_age: int = 0, link: bool = False) -> int:
        cur = self.conn.cursor()
        cur.execute('INSERT INTO channels (name, description, min_level, min_age, link) VALUES (?, ?, ?, ?, ?)',
                    (name, description, min_level, min_age, 1 if link else 0))
        self.conn.commit()
        return cur.lastrowid

    def list_channels(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM channels ORDER BY name')
        return cur.fetchall()

    def user_can_access_channel(self, channel_id: int, user: Optional['User']) -> bool:
        """Return True if a user may join the given channel based on level, age or overrides."""
        if user is None:
            return False
        # Fetch channel restrictions
        cur = self.conn.cursor()
        cur.execute('SELECT min_level, min_age FROM channels WHERE id = ?', (channel_id,))
        row = cur.fetchone()
        if not row:
            return False
        min_level = row['min_level']
        min_age = row['min_age']
        # Age check
        if min_age and min_age > 0:
            age = self.get_user_age(user.id)
            if age is None or age < min_age:
                return False
        if user.level >= min_level:
            return True
        # Override
        cur.execute('SELECT 1 FROM channel_access WHERE channel_id = ? AND user_id = ?', (channel_id, user.id))
        return cur.fetchone() is not None

    def grant_channel_access(self, channel_id: int, user_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT OR IGNORE INTO channel_access (channel_id, user_id) VALUES (?, ?)', (channel_id, user_id))
        self.conn.commit()

    def revoke_channel_access(self, channel_id: int, user_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute('DELETE FROM channel_access WHERE channel_id = ? AND user_id = ?', (channel_id, user_id))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Moderator operations
    def is_channel_moderator(self, channel_id: int, user_id: int) -> bool:
        cur = self.conn.cursor()
        cur.execute('SELECT 1 FROM moderators WHERE user_id = ? AND target_type = ? AND target_id = ?', (user_id, 'channel', channel_id))
        return cur.fetchone() is not None

    def is_global_chat_moderator(self, user_id: int) -> bool:
        cur = self.conn.cursor()
        cur.execute('SELECT 1 FROM moderators WHERE user_id = ? AND target_type = ? AND target_id = 0', (user_id, 'channel'))
        return cur.fetchone() is not None

    # Board moderator checks
    def is_board_moderator(self, board_id: int, user_id: int) -> bool:
        """Return True if user is a moderator for the given message board."""
        cur = self.conn.cursor()
        cur.execute('SELECT 1 FROM moderators WHERE user_id = ? AND target_type = ? AND target_id = ?', (user_id, 'board', board_id))
        return cur.fetchone() is not None

    def is_global_board_moderator(self, user_id: int) -> bool:
        """Return True if user is a global board moderator (target_id=0)."""
        cur = self.conn.cursor()
        cur.execute('SELECT 1 FROM moderators WHERE user_id = ? AND target_type = ? AND target_id = 0', (user_id, 'board'))
        return cur.fetchone() is not None

    def add_moderator(self, user_id: int, target_type: str, target_id: int, perms: str) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT INTO moderators (user_id, target_type, target_id, perms) VALUES (?, ?, ?, ?)', (user_id, target_type, target_id, perms))
        self.conn.commit()

    def remove_moderator(self, user_id: int, target_type: str, target_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute('DELETE FROM moderators WHERE user_id = ? AND target_type = ? AND target_id = ?', (user_id, target_type, target_id))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Sanctions (mutes/bans)
    def mute_user(self, user_id: int, channel_id: Optional[int], expires_at: Optional[str], set_by: int) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT INTO chat_sanctions (user_id, channel_id, action, expires_at, set_by) VALUES (?, ?, ?, ?, ?)',
                    (user_id, channel_id if channel_id else None, 'mute', expires_at, set_by))
        self.conn.commit()

    def ban_user(self, user_id: int, channel_id: Optional[int], expires_at: Optional[str], set_by: int) -> None:
        cur = self.conn.cursor()
        cur.execute('INSERT INTO chat_sanctions (user_id, channel_id, action, expires_at, set_by) VALUES (?, ?, ?, ?, ?)',
                    (user_id, channel_id if channel_id else None, 'ban', expires_at, set_by))
        self.conn.commit()

    def unmute_user(self, user_id: int, channel_id: Optional[int]) -> None:
        cur = self.conn.cursor()
        cur.execute('DELETE FROM chat_sanctions WHERE user_id = ? AND action = ? AND (channel_id IS NULL OR channel_id = ?)', (user_id, 'mute', channel_id))
        self.conn.commit()

    def unban_user(self, user_id: int, channel_id: Optional[int]) -> None:
        cur = self.conn.cursor()
        cur.execute('DELETE FROM chat_sanctions WHERE user_id = ? AND action = ? AND (channel_id IS NULL OR channel_id = ?)', (user_id, 'ban', channel_id))
        self.conn.commit()

    def is_user_muted(self, user_id: int, channel_id: Optional[int]) -> bool:
        cur = self.conn.cursor()
        now_iso = datetime.utcnow().isoformat()
        if channel_id:
            cur.execute('''SELECT 1 FROM chat_sanctions WHERE user_id = ? AND action = 'mute' AND (channel_id IS NULL OR channel_id = ?) AND (expires_at IS NULL OR expires_at > ?)''', (user_id, channel_id, now_iso))
        else:
            cur.execute('''SELECT 1 FROM chat_sanctions WHERE user_id = ? AND action = 'mute' AND channel_id IS NULL AND (expires_at IS NULL OR expires_at > ?)''', (user_id, now_iso))
        return cur.fetchone() is not None

    def is_user_banned(self, user_id: int, channel_id: Optional[int]) -> bool:
        cur = self.conn.cursor()
        now_iso = datetime.utcnow().isoformat()
        if channel_id:
            cur.execute('''SELECT 1 FROM chat_sanctions WHERE user_id = ? AND action = 'ban' AND (channel_id IS NULL OR channel_id = ?) AND (expires_at IS NULL OR expires_at > ?)''', (user_id, channel_id, now_iso))
        else:
            cur.execute('''SELECT 1 FROM chat_sanctions WHERE user_id = ? AND action = 'ban' AND channel_id IS NULL AND (expires_at IS NULL OR expires_at > ?)''', (user_id, now_iso))
        return cur.fetchone() is not None

    # ------------------------------------------------------------------
    # Remote queue operations
    def enqueue_remote_task(self, op_type: str, host: str, endpoint: str, payload: Dict[str, str], max_attempts: int) -> int:
        cur = self.conn.cursor()
        cur.execute('INSERT INTO remote_queue (op_type, host, endpoint, payload, max_attempts) VALUES (?, ?, ?, ?, ?)',
                    (op_type, host, endpoint, json.dumps(payload), max_attempts))
        self.conn.commit()
        return cur.lastrowid

    def get_due_remote_tasks(self, retry_interval: int) -> List[sqlite3.Row]:
        """Return tasks ready for retrying. A task is due if it is pending or failed and the last attempt was more than retry_interval seconds ago."""
        now = datetime.utcnow()
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM remote_queue WHERE status = "pending" OR status = "failed"')
        tasks = []
        for row in cur.fetchall():
            if row['attempts'] == 0:
                tasks.append(row)
            else:
                # Check time since last attempt
                last = row['last_attempt']
                if not last:
                    tasks.append(row)
                else:
                    try:
                        last_dt = datetime.fromisoformat(last)
                        if (now - last_dt).total_seconds() >= retry_interval:
                            tasks.append(row)
                    except Exception:
                        tasks.append(row)
        return tasks

    def mark_remote_task_success(self, task_id: int) -> None:
        cur = self.conn.cursor()
        cur.execute('DELETE FROM remote_queue WHERE id = ?', (task_id,))
        self.conn.commit()

    def increment_remote_task_attempts(self, task_id: int) -> None:
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute('UPDATE remote_queue SET attempts = attempts + 1, last_attempt = ?, status = "pending" WHERE id = ?', (now, task_id))
        self.conn.commit()

    def mark_remote_task_failed(self, task_id: int) -> None:
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute('UPDATE remote_queue SET status = "failed", last_attempt = ? WHERE id = ?', (now, task_id))
        self.conn.commit()

    # Age and date of birth operations
    def get_user_age(self, user_id: int) -> Optional[int]:
        """Return the age of the user in years based on their date of birth in ISO format (YYYY-MM-DD)."""
        # Get dob from user_profiles
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM user_profiles WHERE user_id = ? AND field = ?', (user_id, 'dob'))
        row = cur.fetchone()
        if not row or not row['value']:
            return None
        dob_str = row['value']
        try:
            # Try to parse ISO date
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except Exception:
            # Fallback: try any date format (best effort)
            try:
                dob = datetime.fromisoformat(dob_str).date()
            except Exception:
                return None
        today = datetime.utcnow().date()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        return age

    def get_private_message(self, msg_id: int, user_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT pm.*, u.username as from_user FROM private_messages pm JOIN users u ON u.id = pm.from_user_id WHERE pm.id = ? AND pm.to_user_id = ?', (msg_id, user_id))
        return cur.fetchone()

    def mark_private_message_read(self, msg_id: int) -> None:
        self.conn.execute('UPDATE private_messages SET read = 1 WHERE id = ?', (msg_id,))
        self.conn.commit()

    def delete_private_message(self, msg_id: int, user_id: int) -> None:
        self.conn.execute('DELETE FROM private_messages WHERE id = ? AND to_user_id = ?', (msg_id, user_id))
        self.conn.commit()

    def set_user_level(self, user_id: int, level: int) -> None:
        self.conn.execute('UPDATE users SET level = ? WHERE id = ?', (level, user_id))
        self.conn.commit()

    # ------------------------------------------------------------------
    # Remote thread mapping helpers
    #
    def get_local_thread_id(self, from_host: str, remote_thread_id: str) -> Optional[int]:
        """
        Return the local thread ID mapped to a remote thread identifier. If no
        mapping exists, returns None. The from_host should be the alias
        defined in the [link_hosts] section. remote_thread_id may be
        numeric or string and will be compared as a string.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT local_thread_id FROM remote_thread_map WHERE from_host = ? AND remote_thread_id = ?', (from_host, str(remote_thread_id)))
        row = cur.fetchone()
        return row['local_thread_id'] if row else None

    def insert_remote_thread_map(self, from_host: str, remote_thread_id: str, local_thread_id: int) -> None:
        """
        Insert a mapping from a remote thread ID to a local thread ID. If
        the mapping already exists it will be ignored. This allows
        subsequent posts referencing the same remote thread to be routed
        correctly.
        """
        cur = self.conn.cursor()
        cur.execute('INSERT OR IGNORE INTO remote_thread_map (from_host, remote_thread_id, local_thread_id) VALUES (?, ?, ?)', (from_host, str(remote_thread_id), local_thread_id))
        self.conn.commit()

    def ensure_remote_user(self) -> int:
        """
        Ensure a 'remote' user exists in the users table. Returns the
        user ID of the remote user. If no such user exists, a new user
        with username 'remote' and an empty password is created at
        level 0. This user is used as the author of posts imported from
        remote hosts when the original author cannot be resolved locally.
        """
        # Attempt to fetch existing remote user
        user = self.get_user('remote')
        if user:
            return user['id']
        # Create remote user
        now = datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute('INSERT INTO users (username, password, level, created_at) VALUES (?, ?, ?, ?)', ('remote', '', 0, now))
        self.conn.commit()
        return cur.lastrowid


###############################################################################
# Password hashing helpers
###############################################################################

def hash_password(password: str) -> str:
    """Hash a password using bcrypt or PBKDF2 depending on availability."""
    if not USE_HASHED_PASSWORDS:
        return password
    if HAVE_BCRYPT:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    # Fallback to PBKDF2
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return salt.hex() + '$' + dk.hex()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a stored hash."""
    if not USE_HASHED_PASSWORDS:
        return password == hashed
    if HAVE_BCRYPT:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    # PBKDF2 fallback
    try:
        salt_hex, dk_hex = hashed.split('$')
        salt = bytes.fromhex(salt_hex)
        dk_expected = bytes.fromhex(dk_hex)
        dk_actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
        return dk_actual == dk_expected
    except Exception:
        return False


###############################################################################
# Session and BBS classes
###############################################################################

@dataclass
class User:
    id: int
    username: str
    level: int


class Session:
    """Represents a connected client session."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, server: 'BBS') -> None:
        self.reader = reader
        self.writer = writer
        self.server = server
        self.user: Optional[User] = None
        self.logged_in = False
        self.current_board_id: Optional[int] = None
        # Chat flag: True if this session is currently in the chat room
        self.in_chat = False
        self.peername = writer.get_extra_info('peername')
        # ANSI preference; will be set after login based on user input
        self.use_ansi: bool = True
        # User preference attributes (loaded after login)
        self.pref_editor: str = 'line'  # 'line' or 'full'
        self.pref_cols: int = 0  # preferred column width (0 means unlimited)
        self.pref_rows: int = 0  # preferred number of lines (0 means unlimited)
        self.pref_thread_view: bool = True  # True to show posts grouped by thread
        self.pref_signature_include: bool = True  # include signature on posts/PMs by default
        # Chat nickname and channel
        self.nickname: str = ''
        self.current_channel: str = '#general'
        # Timezone and time format preferences; loaded from config or user prefs
        self.pref_timezone: str = ''
        self.pref_time_format: str = ''
        # Language preference (for future localisation)
        self.pref_language: str = ''

    async def send(self, data: str) -> None:
        """Send raw text to the client."""
        try:
            # Optionally wrap lines according to preferred column width
            data_to_send = data
            wrap_width = getattr(self, 'pref_cols', 0)
            if wrap_width and wrap_width > 0:
                wrapped_lines: List[str] = []
                for line in data_to_send.split('\n'):
                    # Process line in segments of wrap_width
                    while True:
                        # If line contains ANSI codes, wrapping may miscount; but we simply wrap raw characters
                        if len(line) > wrap_width:
                            wrapped_lines.append(line[:wrap_width])
                            line = line[wrap_width:]
                        else:
                            wrapped_lines.append(line)
                            break
                data_to_send = '\n'.join(wrapped_lines)
            # If ANSI is disabled for this session, strip escape codes
            if not self.use_ansi:
                data_to_send = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', data_to_send)
            self.writer.write(data_to_send.encode('utf-8'))
            await self.writer.drain()
        except ConnectionError:
            pass

    async def safe_readline(self) -> Optional[str]:
        """Read a line from the client with idle timeout and telnet cleanup.

        This wrapper uses asyncio.wait_for to enforce the server's idle
        timeout. If the client sends no data for the configured interval,
        the session is closed and None is returned. Telnet control codes
        are stripped from the incoming data. If the connection is closed,
        None is returned as well.
        """
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=self.server.idle_timeout)
        except asyncio.TimeoutError:
            # Idle timeout: inform user and close session
            try:
                await self.send(ANSI_RED + "\nIdle timeout. Disconnecting.\n" + ANSI_RESET)
            except Exception:
                pass
            await self.close()
            return None
        except Exception:
            return None
        if not data:
            return None
        # Clean telnet sequences and decode
        return clean_telnet_input(data).rstrip('\r\n')

    async def prompt(self) -> str:
        """Prompt the user for input and return their response."""
        await self.send(ANSI_GREEN + '> ' + ANSI_RESET)
        data = await self.safe_readline()
        if data is None:
            return ''
        return data

    async def close(self) -> None:
        """Close the connection gracefully."""
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Time formatting helper
    #
    def format_time(self, dt: datetime) -> str:
        """Format a datetime according to the user's or default timezone and time format.

        This uses the timezone and 12/24‑hour settings specified in the configuration
        or the user's preferences. If zoneinfo is unavailable, UTC times will be
        returned. The returned string contains only the time portion (hours:minutes:seconds).
        """
        # Determine timezone
        tz_name = self.pref_timezone or (CONFIG.get('defaults', 'timezone', fallback='UTC') if CONFIG else 'UTC')
        tz = None
        if ZoneInfo is not None:
            try:
                tz = ZoneInfo(tz_name)
            except Exception:
                tz = None
        if tz:
            local_dt = dt.astimezone(tz)
        else:
            local_dt = dt
        # Determine time format (12h or 24h)
        fmt_pref = self.pref_time_format or (CONFIG.get('defaults', 'time_format', fallback='24h') if CONFIG else '24h')
        if fmt_pref.lower().startswith('12'):
            return local_dt.strftime('%I:%M:%S %p')
        else:
            return local_dt.strftime('%H:%M:%S')

    # Helper to broadcast message to all sessions in chat
    async def broadcast_chat(self, message: str, channel: str) -> None:
        """Broadcast a chat message to all sessions in the specified channel.

        The sender will not be filtered out here; callers should send the
        message to the sender separately if desired. Only sessions currently
        in chat and on the same channel will receive the broadcast.
        """
        for sess in self.server.sessions:
            if sess.in_chat and sess.current_channel == channel:
                # Do not send duplicate to the sender if they call broadcast separately
                if sess is self:
                    continue
                await sess.send(message)

    async def handle_login(self) -> bool:
        """Authenticate the user. Returns True if login succeeds."""
        # Ask user whether to enable ANSI colors before sending any colored output
        prompt_ansi = CONFIG.get('prompts', 'use_ansi', fallback='Do you want to enable ANSI colors? (y/n): ') if CONFIG else 'Do you want to enable ANSI colors? (y/n): '
        await self.send(prompt_ansi)
        # Read ANSI preference with idle timeout and telnet cleanup
        resp_line = await self.safe_readline()
        if resp_line is not None:
            self.use_ansi = resp_line.strip().lower().startswith('y')
        # Display MOTD from configuration (color codes will be filtered according to self.use_ansi)
        motd = CONFIG.get('general', 'motd', fallback='') if CONFIG else ''
        if motd:
            await self.send(ANSI_CYAN + "\n" + motd + "\n" + ANSI_RESET)
        # Determine client IP for login throttling
        peer = self.writer.get_extra_info('peername') if self.writer else None
        ip = peer[0] if peer else 'unknown'
        # Loop until login succeeds or user quits
        max_attempts = 3
        for _ in range(max_attempts):
            # Check if IP is blocked
            now_ts = time.time()
            block_until = self.server.blocked_ips.get(ip, 0)
            if block_until > now_ts:
                remaining = int(block_until - now_ts)
                await self.send(ANSI_RED + f"Too many failed attempts. Please try again in {remaining} seconds.\n" + ANSI_RESET)
                await asyncio.sleep(1)
                return False
            username = await self.prompt_username()
            if username is None:
                return False
            # Validate username pattern
            if not valid_username(username):
                await self.send(ANSI_RED + "Invalid username format. Use 3-20 letters, numbers, underscores or hyphens.\n" + ANSI_RESET)
                continue
            user_row = self.server.db.get_user(username)
            if user_row is None:
                # Ask to create new account
                prompt = CONFIG.get('prompts', 'create_account_confirm', fallback="User '{username}' not found. Create new account? (y/n): ")
                await self.send(ANSI_YELLOW + prompt.format(username=username) + ANSI_RESET)
                choice_line = await self.safe_readline()
                if choice_line is None:
                    return False
                if choice_line.lower().startswith('y'):
                    pwd = None
                    while True:
                        p = await self.prompt_password(CONFIG.get('prompts', 'create_password', fallback='Create password: '))
                        if p is None:
                            return False
                        # Validate password complexity
                        if not validate_password(p, self.server.password_complexity):
                            await self.send(ANSI_RED + "Password does not meet complexity requirements. Please try again.\n" + ANSI_RESET)
                            continue
                        pwd = p
                        break
                    if pwd is None:
                        return False
                    hashed = hash_password(pwd)
                    user_id = self.server.db.add_user(username, hashed)
                    self.user = User(id=user_id, username=username, level=0)
                    self.logged_in = True
                    # Load any default preferences (none exist yet)
                    self.load_preferences()
                    await self.send(ANSI_GREEN + CONFIG.get('prompts', 'create_account_success', fallback='Account created successfully!') + "\n" + ANSI_RESET)
                    # Ask profile questions for new user
                    await self.ask_profile_questions()
                    self.server.db.update_last_login(user_id)
                    break
                else:
                    continue
            else:
                # Existing user: ask for password
                pwd = await self.prompt_password(CONFIG.get('prompts', 'password', fallback='Password: '))
                if pwd is None:
                    return False
                # Check password for complexity on creation? Only check when creating new accounts
                if verify_password(pwd, user_row['password']):
                    self.user = User(id=user_row['id'], username=user_row['username'], level=user_row['level'])
                    self.logged_in = True
                    # Load user preferences (before updating ANSI; preferences may override)
                    self.load_preferences()
                    self.server.db.update_last_login(self.user.id)
                    await self.send(ANSI_GREEN + CONFIG.get('prompts', 'welcome_back', fallback='Welcome back, {username}!').format(username=self.user.username) + "\n" + ANSI_RESET)
                    # notify about wall messages
                    messages = self.server.db.list_wall_messages(user_id=self.user.id)
                    unread = [m for m in messages if not m['read']]
                    if unread:
                        await self.send(ANSI_YELLOW + f"You have {len(unread)} new wall message(s).\n" + ANSI_RESET)
                    break
                else:
                    await self.send(ANSI_RED + CONFIG.get('prompts', 'login_invalid_password', fallback='Invalid password.') + "\n" + ANSI_RESET)
                    # Record failed attempt for IP
                    ts_now = time.time()
                    attempts = self.server.failed_logins.get(ip, [])
                    # Remove expired attempts outside window
                    window_start = ts_now - self.server.fail_window
                    attempts = [t for t in attempts if t >= window_start]
                    attempts.append(ts_now)
                    self.server.failed_logins[ip] = attempts
                    # Check if threshold exceeded
                    if len(attempts) >= self.server.max_failed_attempts:
                        # Block IP for block_duration
                        self.server.blocked_ips[ip] = ts_now + self.server.block_duration
                        await self.send(ANSI_RED + "Too many failed login attempts. You are temporarily blocked.\n" + ANSI_RESET)
                        return False
                    continue
        else:
            await self.send(ANSI_RED + CONFIG.get('prompts', 'login_too_many', fallback='Too many failed login attempts. Goodbye!') + "\n" + ANSI_RESET)
            # Block IP after overall login attempts
            ts_now = time.time()
            self.server.blocked_ips[ip] = ts_now + self.server.block_duration
            return False
        return True

    async def prompt_username(self) -> Optional[str]:
        prompt = CONFIG.get('prompts', 'username', fallback="Username (or 'quit' to exit): ")
        await self.send(prompt)
        data = await self.safe_readline()
        if data is None:
            return None
        username = data.strip()
        if username.lower() == 'quit':
            return None
        return username

    async def prompt_password(self, prompt_text: str) -> Optional[str]:
        """Prompt for a password.

        Note: Telnet does not support hidden password input without option
        negotiation. For simplicity we show the password plainly. The input
        will time out after the server's idle timeout. If the session times
        out or disconnects, None is returned.
        """
        await self.send(prompt_text)
        data = await self.safe_readline()
        if data is None:
            return None
        return data.strip()

    async def main_menu(self) -> None:
        """Display the main menu and handle user selection."""
        while True:
            # Check for external ANSI graphic for main menu
            graphic_path = Path(MENU_DIR) / 'main_menu.ans'
            if graphic_path.exists():
                try:
                    with open(graphic_path, 'r', encoding='utf-8', errors='ignore') as gf:
                        ansi_data = gf.read()
                    await self.send(ansi_data)
                except Exception:
                    pass
            else:
                # Build menu from configuration
                title = CONFIG.get('menus', 'main_title', fallback='Main Menu') if CONFIG else 'Main Menu'
                options = CONFIG.get('menus', 'main_options', fallback='1) Message Boards\n2) File Boards\n3) Chat Room\n4) Wall\n5) Door Games\n6) User Settings\n0) Log Off') if CONFIG else '1) Message Boards\n2) File Boards\n3) Chat Room\n4) Wall\n5) Door Games\n6) User Settings\n0) Log Off'
                menu_lines = [ANSI_BOLD + ANSI_BLUE + f"\n{title}\n" + ANSI_RESET, options]
                # Add sysop option if applicable
                if self.user and self.user.level >= 10:
                    sysop_opt = CONFIG.get('menus', 'sysop_option', fallback='7) SysOp Console') if CONFIG else '7) SysOp Console'
                    menu_lines.append(sysop_opt)
                menu_str = "\n".join(menu_lines) + "\n"
                await self.send(menu_str)
            choice = await self.prompt()
            if choice == '1':
                await self.message_boards_menu()
            elif choice == '2':
                # Show file areas (formerly file boards)
                await self.file_areas_menu()
            elif choice == '3':
                await self.chat_room()
            elif choice == '4':
                await self.wall_menu()
            elif choice == '5':
                await self.pm_menu()
            elif choice == '6':
                await self.door_games_menu()
            elif choice == '7':
                await self.user_settings_menu()
            elif choice == '8' and self.user and self.user.level >= 10:
                await self.sysop_menu()
            elif choice == '0':
                # Ask user if they want to leave a wall message
                prompt = CONFIG.get('prompts', 'logoff_wall', fallback='Would you like to leave a wall message before logging off? (y/n): ') if CONFIG else 'Would you like to leave a wall message before logging off? (y/n): '
                await self.send(prompt)
                resp = await self.reader.readline()
                if resp and resp.decode('utf-8', 'ignore').strip().lower().startswith('y'):
                    await self.logoff_wall_message()
                await self.send(ANSI_CYAN + "Goodbye!\n" + ANSI_RESET)
                return
            else:
                await self.send(ANSI_RED + "Invalid choice.\n" + ANSI_RESET)

    # Message boards
    async def message_boards_menu(self) -> None:
        while True:
            boards = [b for b in self.server.db.list_boards() if self.server.db.user_can_access_board('msg', b['id'], self.user)]
            menu_lines = [ANSI_BOLD + ANSI_MAGENTA + "\nMessage Boards:\n" + ANSI_RESET]
            for b in boards:
                min_age = b['min_age'] if 'min_age' in b.keys() else 0
                age_str = f", MinAge {min_age}" if min_age else ""
                menu_lines.append(f"{b['id']}) {b['name']} - {b['description']} (MinLvl {b['min_level']}{age_str})")
            menu_lines.append("0) Back to Main Menu")
            await self.send("\n".join(menu_lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            try:
                board_id = int(choice)
            except ValueError:
                await self.send(ANSI_RED + "Invalid board.\n" + ANSI_RESET)
                continue
            # Check access
            if not self.server.db.user_can_access_board('msg', board_id, self.user):
                await self.send(ANSI_RED + "Access denied to this board.\n" + ANSI_RESET)
                continue
            board = self.server.db.get_board(board_id)
            if not board:
                await self.send(ANSI_RED + "Board not found.\n" + ANSI_RESET)
                continue
            await self.board_view(board)

    async def board_view(self, board: sqlite3.Row) -> None:
        while True:
            threads = self.server.db.list_threads(board['id'])
            lines = [ANSI_BOLD + ANSI_MAGENTA + f"\nBoard: {board['name']}\n" + ANSI_RESET]
            for t in threads:
                created = t['created_at'][:19].replace('T', ' ')
                lines.append(f"{t['id']}) {t['title']} (by {t['author']}, {created})")
            lines.append("n) New Thread")
            lines.append("0) Back to Boards")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice.lower() == 'n':
                await self.create_thread(board['id'])
            else:
                try:
                    thread_id = int(choice)
                except ValueError:
                    await self.send(ANSI_RED + "Invalid thread.\n" + ANSI_RESET)
                    continue
                # Choose view based on user preference
                if getattr(self, 'pref_thread_view', True):
                    await self.thread_view(board['id'], thread_id)
                else:
                    await self.thread_view_sequential(board['id'], thread_id)

    async def create_thread(self, board_id: int) -> None:
        await self.send(ANSI_CYAN + "Enter thread title: " + ANSI_RESET)
        title = await self.reader.readline()
        if not title:
            return
        title_str = title.decode('utf-8', 'ignore').strip()
        # Sanitize title to remove control codes
        title_str = sanitize_text(title_str)
        if not title_str:
            return
        thread_id = self.server.db.add_thread(board_id, title_str, self.user.id)  # type: ignore
        await self.send(ANSI_GREEN + "Thread created.\n" + ANSI_RESET)
        # If this board is configured as a linked board, sync the new thread to peers
        # Compose payload with minimal information
        try:
            board_row = self.server.db.get_board(board_id)
            board_name = board_row['name'] if board_row else ''
            payload = {
                'id': thread_id,
                'title': title_str,
                'author': self.user.username if self.user else '',
                'created_at': datetime.utcnow().isoformat(),
                'type': 'thread',
            }
            # Fire and forget; do not await
            asyncio.create_task(self.server.sync_link_board(board_name, payload))
        except Exception:
            pass
        await self.thread_view(board_id, thread_id)

    async def thread_view(self, board_id: int, thread_id: int) -> None:
        while True:
            # Determine whether board is moderated and whether current user is a moderator
            board = self.server.db.get_board(board_id)
            moderated = board['moderated'] if board and 'moderated' in board.keys() else 0
            is_mod = False
            if self.user:
                is_mod = (self.user.level >= 255 or self.server.db.is_board_moderator(board_id, self.user.id) or self.server.db.is_global_board_moderator(self.user.id))
            # Fetch posts; include unapproved if user is moderator
            if moderated and is_mod:
                # Fetch all posts with approved status
                cur = self.server.db.conn.cursor()
                cur.execute('SELECT posts.*, users.username AS author FROM posts JOIN users ON users.id = posts.author_id WHERE thread_id = ? ORDER BY created_at', (thread_id,))
                posts = cur.fetchall()
            else:
                posts = self.server.db.list_posts(thread_id)
            header = ANSI_BOLD + ANSI_CYAN + ("\nThread is empty.\n" if not posts else "\nPosts:\n") + ANSI_RESET
            lines = [header]
            for p in posts:
                created = p['created_at'][:19].replace('T', ' ')
                content = p['content']
                status = ''
                if moderated and p['approved'] == 0:
                    status = ' (Pending)'
                # Fetch attachments for this post
                att_rows = self.server.db.list_attachments(p['id'])  # type: ignore
                attach_info = ''
                if att_rows:
                    names = [att['filename'] for att in att_rows]
                    attach_info = '\nAttachments: ' + ', '.join(names)
                lines.append(f"[{p['id']}] {p['author']} @ {created}{status}\n{content}{attach_info}\n")
            # If user is moderator and there are unapproved posts, offer approval options
            menu_options = []
            menu_options.append("p) Post a reply")
            if moderated and is_mod and any(p['approved'] == 0 for p in posts):
                menu_options.append("a) Approve post")
                menu_options.append("d) Delete post")
            menu_options.append("0) Back to thread list")
            lines.extend(menu_options)
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice.lower() == 'p':
                content = await self.edit_message()
                if content is None:
                    await self.send(ANSI_YELLOW + "Post cancelled.\n" + ANSI_RESET)
                else:
                    # Append signature if user preference
                    if self.pref_signature_include:
                        sig = self.server.db.get_user_signature(self.user.id)  # type: ignore
                        if sig:
                            content = content + "\n--\n" + sig
                    # Sanitize content to remove ANSI and control codes
                    content = sanitize_text(content)
                    # Determine approval: if moderated and not moderator, mark unapproved
                    approved = True
                    if moderated and not is_mod:
                        approved = False
                    post_id = self.server.db.add_post(thread_id, self.user.id, content, approved)  # type: ignore
                    await self.send(ANSI_GREEN + ("Message posted (pending approval).\n" if not approved else "Message posted.\n") + ANSI_RESET)
                    # Offer attachment upload via ZModem for this post. Only local attachments are supported.
                    try:
                        await self.send(ANSI_CYAN + "Attach a file to this post via ZModem? (y/n): " + ANSI_RESET)
                        attach_resp = await self.reader.readline()
                        if attach_resp and attach_resp.decode('utf-8', 'ignore').strip().lower().startswith('y'):
                            await self.zmodem_receive_attachment(post_id)
                    except Exception:
                        # Ignore attachment errors
                        pass
                    # If this board is a linked board, sync the new post to peers
                    try:
                        board_row = self.server.db.get_board(board_id)
                        board_name = board_row['name'] if board_row else ''
                        payload = {
                            'id': post_id,
                            'thread_id': thread_id,
                            'author': self.user.username if self.user else '',
                            'content': content,
                            'created_at': datetime.utcnow().isoformat(),
                            'type': 'post',
                            'approved': 1 if approved else 0,
                        }
                        # Include pinned/exempt flags for synchronization
                        try:
                            pinned_flag, exempt_flag = self.server.db.get_post_flags(post_id)
                            payload['pinned'] = int(pinned_flag)
                            payload['exempt'] = int(exempt_flag)
                        except Exception:
                            pass
                        asyncio.create_task(self.server.sync_link_board(board_name, payload))
                    except Exception:
                        pass
            elif choice.lower() == 'a' and moderated and is_mod:
                # Approve a pending post
                await self.send(ANSI_CYAN + "Enter post ID to approve: " + ANSI_RESET)
                pid_line = await self.reader.readline()
                if not pid_line:
                    continue
                try:
                    pid = int(pid_line.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid ID.\n" + ANSI_RESET)
                    continue
                # Update approval
                cur = self.server.db.conn.cursor()
                cur.execute('UPDATE posts SET approved = 1 WHERE id = ?', (pid,))
                self.server.db.conn.commit()
                await self.send(ANSI_GREEN + "Post approved.\n" + ANSI_RESET)
            elif choice.lower() == 'd' and moderated and is_mod:
                await self.send(ANSI_CYAN + "Enter post ID to delete: " + ANSI_RESET)
                pid_line = await self.reader.readline()
                if not pid_line:
                    continue
                try:
                    pid = int(pid_line.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid ID.\n" + ANSI_RESET)
                    continue
                cur = self.server.db.conn.cursor()
                cur.execute('DELETE FROM posts WHERE id = ?', (pid,))
                self.server.db.conn.commit()
                await self.send(ANSI_GREEN + "Post deleted.\n" + ANSI_RESET)

    # File areas (formerly file boards)
    async def file_areas_menu(self) -> None:
        # For simplicity, file boards use the same boards table as message boards
        while True:
            boards = [b for b in self.server.db.list_file_areas() if self.server.db.user_can_access_board('file', b['id'], self.user)]
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nFile Areas:\n" + ANSI_RESET]
            for b in boards:
                min_age = b['min_age'] if 'min_age' in b.keys() else 0
                age_str = f", MinAge {min_age}" if min_age else ""
                lines.append(f"{b['id']}) {b['name']} - {b['description']} (MinLvl {b['min_level']}{age_str})")
            lines.append("0) Back to Main Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            try:
                b_id = int(choice)
            except ValueError:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                continue
            if not self.server.db.user_can_access_board('file', b_id, self.user):
                await self.send(ANSI_RED + "Access denied to this board.\n" + ANSI_RESET)
                continue
            board = self.server.db.conn.execute('SELECT * FROM file_areas WHERE id = ?', (b_id,)).fetchone()
            if not board:
                await self.send(ANSI_RED + "Board not found.\n" + ANSI_RESET)
                continue
            await self.file_area_view(board)

    async def file_area_view(self, board: sqlite3.Row) -> None:
        while True:
            files = self.server.db.conn.execute('SELECT * FROM files WHERE board_id = ? ORDER BY uploaded_at DESC', (board['id'],)).fetchall()
            lines = [ANSI_BOLD + ANSI_MAGENTA + f"\nFile Area: {board['name']}\n" + ANSI_RESET]
            for f in files:
                up_time = f['uploaded_at'][:19].replace('T', ' ')
                lines.append(f"{f['id']}) {f['filename']} ({f['size']} bytes, by user {f['uploader_id']}, {up_time})")
            # Provide options: plain text upload, ZModem receive
            lines.append("u) Upload file (paste text)")
            lines.append("z) Receive file via ZModem")
            lines.append("0) Back to File Areas")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice.lower() == 'u':
                await self.file_upload(board)
            elif choice.lower() == 'z':
                await self.zmodem_receive(board)
            else:
                try:
                    file_id = int(choice)
                except ValueError:
                    await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                    continue
                # Sub‑menu for file actions
                await self.file_actions(file_id)

    async def file_upload(self, board: sqlite3.Row) -> None:
        # Note: Transferring binary files over telnet is impractical. Instead,
        # this upload function allows the user to paste text content that will
        # be saved to a file. Real file transfer would require Zmodem/Ymodem or
        # other protocols beyond this example.
        await self.send(ANSI_CYAN + "Enter filename: " + ANSI_RESET)
        data = await self.reader.readline()
        if not data:
            return
        filename = data.decode('utf-8', 'ignore').strip()
        await self.send(ANSI_CYAN + "Enter file content. End with a single '.' on a line by itself.\n" + ANSI_RESET)
        lines_in: List[str] = []
        while True:
            line_data = await self.reader.readline()
            if not line_data:
                return
            line = line_data.decode('utf-8', 'ignore').rstrip('\r\n')
            if line == '.':
                break
            lines_in.append(line)
        content = '\n'.join(lines_in)
        # Enforce maximum file size. The default max size is read from
        # configuration (in bytes). If the file exceeds the limit, abort.
        max_sz = 0
        try:
            # Check per‑file area setting first
            if CONFIG and CONFIG.has_section('file_areas') and CONFIG.has_option('file_areas', 'max_file_size'):
                max_sz = int(CONFIG.get('file_areas', 'max_file_size', fallback='0'))
            else:
                # Fallback to general default
                max_sz = int(CONFIG.get('general', 'max_file_size', fallback='0')) if CONFIG else 0
        except Exception:
            max_sz = 0
        # Save to disk
        dir_path = Path('uploads') / str(board['id'])
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        size = file_path.stat().st_size
        # Check against max size
        if max_sz and size > max_sz:
            # Delete the file and notify
            try:
                file_path.unlink()
            except Exception:
                pass
            await self.send(ANSI_RED + f"File exceeds maximum allowed size ({max_sz} bytes). Upload aborted.\n" + ANSI_RESET)
            return
        now = datetime.utcnow().isoformat()
        self.server.db.conn.execute(
            'INSERT INTO files (board_id, filename, uploader_id, uploaded_at, size, path) VALUES (?, ?, ?, ?, ?, ?)',
            (board['id'], filename, self.user.id, now, size, str(file_path)),
        )
        self.server.db.conn.commit()
        await self.send(ANSI_GREEN + "File uploaded successfully.\n" + ANSI_RESET)
        # If this file area is linked, enqueue for synchronization. Determine area name.
        area_name = board['name']
        # Build payload: include filename, uploader, size, timestamp and content encoded in base64
        try:
            import base64
            with open(file_path, 'rb') as fh:
                content_bytes = fh.read()
            b64 = base64.b64encode(content_bytes).decode('ascii')
        except Exception:
            b64 = ''
        file_payload = {
            'filename': filename,
            'size': size,
            'content': b64,
            'uploader': self.user.username,
            'uploaded_at': now,
            # Include pinned/exempt flags for remote sync; new uploads are not pinned/exempt
            'pinned': 0,
            'exempt': 0,
        }
        # Queue remote sync
        await self.server.sync_link_area(area_name, file_payload)

    async def file_download(self, file_id: int) -> None:
        # Again, binary transfer is not implemented. We'll simply display the
        # contents of the file. For binary files, output will be gibberish.
        file_row = self.server.db.conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
        if not file_row:
            await self.send(ANSI_RED + "File not found.\n" + ANSI_RESET)
            return
        path = file_row['path']
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            await self.send(ANSI_CYAN + f"\n--- {file_row['filename']} ---\n" + ANSI_RESET)
            await self.send(data + "\n")
        except FileNotFoundError:
            await self.send(ANSI_RED + "File is missing on server.\n" + ANSI_RESET)

    async def file_actions(self, file_id: int) -> None:
        """Present actions for a selected file: view or download via ZModem."""
        file_row = self.server.db.conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
        if not file_row:
            await self.send(ANSI_RED + "File not found.\n" + ANSI_RESET)
            return
        while True:
            await self.send(ANSI_CYAN + f"Selected file: {file_row['filename']}\n" + ANSI_RESET)
            await self.send("1) View as text\n2) Download via ZModem\n0) Cancel\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice == '1':
                await self.file_download(file_id)
                return
            elif choice == '2':
                await self.zmodem_send(file_row)
                return
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def zmodem_send(self, file_row: sqlite3.Row) -> None:
        """Send a file to the user via ZModem using the external 'sz' command."""
        # Check for sz command
        sz_path = shutil.which('sz')
        if not sz_path:
            await self.send(ANSI_RED + "ZModem send command 'sz' is not available on the server.\n" + ANSI_RESET)
            return
        path = file_row['path']
        await self.send(ANSI_YELLOW + "Starting ZModem send. Please initiate ZModem receive in your client.\n" + ANSI_RESET)
        # Launch sz command
        proc = await asyncio.create_subprocess_exec(
            sz_path, path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async def to_client():
            while True:
                data = await proc.stdout.read(1024)
                if not data:
                    break
                try:
                    self.writer.write(data)
                    await self.writer.drain()
                except ConnectionError:
                    break
        async def from_client():
            # Read from client to feed into sz (for acknowledgements)
            while True:
                try:
                    data = await self.reader.read(1024)
                except Exception:
                    break
                if not data:
                    break
                try:
                    proc.stdin.write(data)
                    await proc.stdin.drain()
                except Exception:
                    break
        await asyncio.gather(to_client(), from_client())
        await proc.wait()
        await self.send(ANSI_GREEN + "ZModem send completed.\n" + ANSI_RESET)

    async def zmodem_receive(self, board: sqlite3.Row) -> None:
        """Receive a file from the user via ZModem using the external 'rz' command."""
        rz_path = shutil.which('rz')
        if not rz_path:
            await self.send(ANSI_RED + "ZModem receive command 'rz' is not available on the server.\n" + ANSI_RESET)
            return
        await self.send(ANSI_YELLOW + "Starting ZModem receive. Please initiate ZModem send in your client.\n" + ANSI_RESET)
        # Ensure directory exists for uploads via zmodem
        dir_path = Path('uploads') / str(board['id'])
        dir_path.mkdir(parents=True, exist_ok=True)
        # We run rz in this directory so it writes incoming files here
        proc = await asyncio.create_subprocess_exec(
            rz_path,
            cwd=str(dir_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async def to_client():
            while True:
                data = await proc.stdout.read(1024)
                if not data:
                    break
                try:
                    self.writer.write(data)
                    await self.writer.drain()
                except ConnectionError:
                    break
        async def from_client():
            while True:
                try:
                    data = await self.reader.read(1024)
                except Exception:
                    break
                if not data:
                    break
                try:
                    proc.stdin.write(data)
                    await proc.stdin.drain()
                except Exception:
                    break
        await asyncio.gather(to_client(), from_client())
        await proc.wait()
        # After receiving files, register them in database
        # Use directory listing to find new files
        for file_path in dir_path.iterdir():
            # Skip directories
            if file_path.is_dir():
                continue
            # Avoid duplicates by checking if path already in DB
            row = self.server.db.conn.execute('SELECT * FROM files WHERE path = ?', (str(file_path),)).fetchone()
            if row:
                continue
            size = file_path.stat().st_size
            # Enforce maximum file size using configuration
            max_sz = 0
            try:
                # Per‑file area setting overrides global
                if CONFIG and CONFIG.has_section('file_areas') and CONFIG.has_option('file_areas', 'max_file_size'):
                    max_sz = int(CONFIG.get('file_areas', 'max_file_size', fallback='0'))
                else:
                    max_sz = int(CONFIG.get('general', 'max_file_size', fallback='0')) if CONFIG else 0
            except Exception:
                max_sz = 0
            if max_sz and size > max_sz:
                # Delete file and skip
                try:
                    file_path.unlink()
                except Exception:
                    pass
                await self.send(ANSI_RED + f"Received file {file_path.name} exceeds maximum allowed size ({max_sz} bytes). Skipped.\n" + ANSI_RESET)
                continue
            now = datetime.utcnow().isoformat()
            self.server.db.conn.execute(
                'INSERT INTO files (board_id, filename, uploader_id, uploaded_at, size, path) VALUES (?, ?, ?, ?, ?, ?)',
                (board['id'], file_path.name, self.user.id if self.user else 0, now, size, str(file_path)),
            )
            self.server.db.conn.commit()
            # After saving, queue remote sync if this area is linked
            area_name = board['name']
            try:
                import base64
                with open(file_path, 'rb') as fh:
                    content_bytes = fh.read()
                b64 = base64.b64encode(content_bytes).decode('ascii')
            except Exception:
                b64 = ''
            file_payload = {
                'filename': file_path.name,
                'size': size,
                'content': b64,
                'uploader': self.user.username if self.user else 'anonymous',
                'uploaded_at': now,
            }
            await self.server.sync_link_area(area_name, file_payload)

    async def zmodem_receive_attachment(self, post_id: int) -> None:
        """Receive an attachment via ZModem and associate it with a post.

        Attachments are stored in a directory under ``attachments/<post_id>``. Files
        larger than 20 MiB are rejected. The 'rz' command must be available.
        """
        rz_path = shutil.which('rz')
        if not rz_path:
            await self.send(ANSI_RED + "ZModem receive command 'rz' is not available on the server.\n" + ANSI_RESET)
            return
        await self.send(ANSI_YELLOW + "Starting ZModem receive for attachment. Please initiate ZModem send in your client.\n" + ANSI_RESET)
        # Create directory for this post's attachments
        dir_path = Path('attachments') / str(post_id)
        dir_path.mkdir(parents=True, exist_ok=True)
        # Launch rz in this directory
        proc = await asyncio.create_subprocess_exec(
            rz_path,
            cwd=str(dir_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async def to_client():
            while True:
                data = await proc.stdout.read(1024)
                if not data:
                    break
                try:
                    self.writer.write(data)
                    await self.writer.drain()
                except Exception:
                    break
        async def from_client():
            while True:
                try:
                    data = await self.reader.read(1024)
                except Exception:
                    break
                if not data:
                    break
                try:
                    proc.stdin.write(data)
                    await proc.stdin.drain()
                except Exception:
                    break
        await asyncio.gather(to_client(), from_client())
        await proc.wait()
        # Process received files
        max_attachment = 20 * 1024 * 1024  # 20 MB limit
        for fpath in dir_path.iterdir():
            if fpath.is_dir():
                continue
            size = fpath.stat().st_size
            # Enforce limit
            if size > max_attachment:
                try:
                    fpath.unlink()
                except Exception:
                    pass
                await self.send(ANSI_RED + f"Attachment {fpath.name} exceeds maximum allowed size (20 MB). Skipped.\n" + ANSI_RESET)
                continue
            # Avoid duplicate attachments
            existing = self.server.db.conn.execute('SELECT 1 FROM attachments WHERE path = ?', (str(fpath),)).fetchone()
            if existing:
                continue
            # Insert into attachments table
            self.server.db.add_attachment(post_id, fpath.name, str(fpath), size)
            await self.send(ANSI_GREEN + f"Attachment {fpath.name} uploaded successfully.\n" + ANSI_RESET)
        await self.send(ANSI_GREEN + "ZModem receive completed.\n" + ANSI_RESET)

    # Wall
    async def wall_menu(self) -> None:
        while True:
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nWall\n" + ANSI_RESET]
            messages = self.server.db.list_wall_messages(user_id=self.user.id)  # type: ignore
            for m in messages:
                to = f" -> {m['to_user']}" if m['to_user'] else ""
                created = m['created_at'][:19].replace('T', ' ')
                lines.append(f"[{m['id']}] {m['from_user']}{to}: {m['content']} ({created})")
            lines.append("p) Post new wall message")
            lines.append("0) Back to Main Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice.lower() == 'p':
                await self.send(ANSI_CYAN + "Enter recipient username (leave blank for public): " + ANSI_RESET)
                data = await self.reader.readline()
                if not data:
                    return
                to_user = data.decode('utf-8', 'ignore').strip()
                if to_user:
                    u_row = self.server.db.get_user(to_user)
                    if not u_row:
                        await self.send(ANSI_RED + "User not found.\n" + ANSI_RESET)
                        continue
                    to_id = u_row['id']
                else:
                    to_id = None
                await self.send(ANSI_CYAN + "Enter your message (single line): " + ANSI_RESET)
                msg_data = await self.reader.readline()
                if not msg_data:
                    return
                msg = msg_data.decode('utf-8', 'ignore').strip()
                msg = sanitize_text(msg)
                self.server.db.post_wall_message(self.user.id, to_id, msg)  # type: ignore
                await self.send(ANSI_GREEN + "Message posted.\n" + ANSI_RESET)

    async def _line_editor(self) -> Optional[str]:
        """A simple line‑based text editor. Users type lines until they enter '/save' on a new line.

        Returning None cancels the edit (on '/abort')."""
        await self.send(ANSI_CYAN + "Enter your message. Commands: /save to finish, /abort to cancel, /search <pattern> to search, /replace <old> <new> to replace.\n" + ANSI_RESET)
        lines: List[str] = []
        line_no = 1
        search_pattern: Optional[str] = None
        while True:
            # Show line number prompt
            await self.send(f"{line_no:02d}> ")
            data = await self.reader.readline()
            if not data:
                return None
            line = data.decode('utf-8', 'ignore').rstrip('\r\n')
            # Commands
            if line.startswith('/save'):
                return '\n'.join(lines)
            if line.startswith('/abort'):
                return None
            if line.startswith('/search'):
                parts = line.split(' ', 1)
                if len(parts) == 2 and parts[1]:
                    search_pattern = parts[1]
                    # Find next occurrence in current buffer
                    found = False
                    for idx, l in enumerate(lines):
                        if search_pattern.lower() in l.lower():
                            await self.send(ANSI_YELLOW + f"Found on line {idx+1}: {l}\n" + ANSI_RESET)
                            found = True
                            break
                    if not found:
                        await self.send(ANSI_RED + "Not found.\n" + ANSI_RESET)
                    continue
                else:
                    await self.send(ANSI_RED + "Usage: /search <pattern>\n" + ANSI_RESET)
                    continue
            if line.startswith('/replace'):
                parts = line.split(' ', 2)
                if len(parts) == 3:
                    old = parts[1]
                    new = parts[2]
                    if not old:
                        await self.send(ANSI_RED + "Replacement failed: old pattern empty.\n" + ANSI_RESET)
                        continue
                    count = 0
                    for i in range(len(lines)):
                        if old in lines[i]:
                            lines[i] = lines[i].replace(old, new)
                            count += 1
                    await self.send(ANSI_GREEN + f"Replaced {count} occurrence(s).\n" + ANSI_RESET)
                else:
                    await self.send(ANSI_RED + "Usage: /replace <old> <new>\n" + ANSI_RESET)
                continue
            # Otherwise treat as text
            lines.append(line)
            line_no += 1

    async def edit_message(self) -> Optional[str]:
        """Select the appropriate editor based on user preferences."""
        # If user prefers fullscreen editor
        if getattr(self, 'pref_editor', 'line') == 'full':
            return await self.fullscreen_editor()
        # Default to line editor
        return await self._line_editor()

    async def fullscreen_editor(self, initial_text: str = '') -> Optional[str]:
        """A simple fullscreen text editor using curses.

        Supports arrow key navigation, insert/overwrite mode, and basic
        markup insertion (bold, italic, underline, strikethrough). The
        editor displays a status bar with available commands. On save
        (Ctrl‑S) the edited text is returned; on quit (Ctrl‑Q) None is
        returned. Spell checking is available via Ctrl‑W if the 'enchant'
        library is installed; suggestions for the current word under the
        cursor will be displayed in the status bar.

        Note: Because curses is not asynchronous, this method offloads the
        editing to a separate thread via run_in_executor. Terminal window
        dimensions are honoured, but user preference for columns/rows will
        cap the editing area. Formatting tags are simple BBCode-like tags
        inserted when toggling bold (/b), italic (/i), underline (/u) and
        strikethrough (/s).
        """
        import curses
        import textwrap
        # Try to import enchant for spell checking; optional
        try:
            import enchant  # type: ignore
            speller = enchant.Dict('en_US')  # fallback to US English
        except Exception:
            speller = None  # type: ignore

        # Determine editing area size based on preferences and terminal size
        pref_cols = int(getattr(self, 'pref_cols', 0) or 0)
        pref_rows = int(getattr(self, 'pref_rows', 0) or 0)

        def run_editor() -> Optional[str]:
            # The actual blocking curses editor function
            def editor(stdscr) -> Optional[str]:
                curses.curs_set(1)
                stdscr.clear()
                curses.noecho()
                curses.cbreak()
                stdscr.keypad(True)
                max_y, max_x = stdscr.getmaxyx()
                # Use reserved bottom line for status bar
                edit_h = pref_rows if pref_rows > 0 and pref_rows < max_y - 1 else max_y - 1
                edit_w = pref_cols if pref_cols > 0 and pref_cols < max_x else max_x
                # Prepare initial lines
                lines = initial_text.split('\n') if initial_text else ['']
                # Ensure at least one line
                if not lines:
                    lines = ['']
                cursor_y, cursor_x = 0, 0
                insert_mode = True
                # Markup states
                markup_state = {'b': False, 'i': False, 'u': False, 's': False}

                # Store search pattern across repeated Ctrl+W presses
                search_pattern: Optional[str] = None

                # Helper to redraw screen
                def redraw():
                    stdscr.erase()
                    # Draw editing area
                    for y in range(edit_h):
                        if y < len(lines):
                            text = lines[y]
                        else:
                            text = ''
                        # Wrap text for the display width
                        disp = text[:edit_w].ljust(edit_w)
                        try:
                            stdscr.addstr(y, 0, disp)
                        except curses.error:
                            pass
                    # Build status bar text
                    mode = 'INS' if insert_mode else 'OVR'
                    markup_flags = ''.join([k.upper() for k, v in markup_state.items() if v])
                    # Build left portion of status bar with commands (nano-style)
                    status_left = f"Ctrl+O Write  Ctrl+X Exit  {mode}"
                    if markup_flags:
                        status_left += f" [{markup_flags}]"
                    status_right = "Ctrl+W Where Is  Ctrl+\\ Replace  Ctrl+B Bold  Ctrl+I Italic  Ctrl+U Underline  Ctrl+T Strike  Ctrl+K Spell"
                    status = (status_left + ' | ' + status_right)[:max_x]
                    try:
                        stdscr.addstr(edit_h, 0, status.ljust(max_x), curses.A_REVERSE)
                    except curses.error:
                        pass
                    # Position cursor within bounds
                    cy = min(cursor_y, edit_h - 1)
                    cx = min(cursor_x, edit_w - 1)
                    stdscr.move(cy, cx)
                    stdscr.refresh()
                
                def toggle_markup(tag: str):
                    """Toggle markup state and insert tags at cursor."""
                    nonlocal cursor_y, cursor_x
                    # Determine tag text
                    start_tag = f"[{tag}]"
                    end_tag = f"[/{tag}]"
                    if markup_state[tag]:
                        # insert end tag
                        insert_text(end_tag)
                        markup_state[tag] = False
                    else:
                        insert_text(start_tag)
                        markup_state[tag] = True
                
                def insert_text(txt: str):
                    nonlocal cursor_y, cursor_x
                    # Insert or overwrite text at current cursor
                    for ch in txt:
                        insert_char(ch)
                
                def insert_char(ch: str):
                    nonlocal cursor_y, cursor_x, lines
                    # Ensure current line exists
                    while cursor_y >= len(lines):
                        lines.append('')
                    line = lines[cursor_y]
                    if ch == '\n':
                        # Split line at cursor
                        before = line[:cursor_x]
                        after = line[cursor_x:]
                        lines[cursor_y] = before
                        lines.insert(cursor_y + 1, after)
                        cursor_y += 1
                        cursor_x = 0
                        return
                    if insert_mode:
                        line = line[:cursor_x] + ch + line[cursor_x:]
                    else:
                        if cursor_x < len(line):
                            line = line[:cursor_x] + ch + line[cursor_x + 1:]
                        else:
                            line = line + ch
                    lines[cursor_y] = line
                    cursor_x += 1

                # Spell check helper: check word at cursor
                def do_spell_check():
                    if not speller:
                        return
                    # Find word boundaries around cursor
                    if cursor_y >= len(lines):
                        return
                    line = lines[cursor_y]
                    if not line:
                        return
                    # Determine start and end of current word
                    left = cursor_x
                    right = cursor_x
                    while left > 0 and line[left-1].isalnum():
                        left -= 1
                    while right < len(line) and line[right].isalnum():
                        right += 1
                    word = line[left:right]
                    if not word or word.isspace():
                        return
                    if speller.check(word):
                        suggestion = "OK"
                    else:
                        suggs = speller.suggest(word)
                        suggestion = ', '.join(suggs[:3]) if suggs else 'No suggestions'
                    # Show suggestions in status bar for a moment
                    msg = f"Spell: {word} -> {suggestion}"
                    stdscr.addstr(edit_h, 0, msg[:max_x].ljust(max_x), curses.A_REVERSE)
                    stdscr.refresh()
                    curses.napms(1500)
                
                redraw()
                while True:
                    ch = stdscr.getch()
                    # Exit: Ctrl+X (24) or ESC (if KEY_EXIT)
                    if ch in (curses.KEY_EXIT, 24):
                        return None
                    # Save: Ctrl+O (15)
                    if ch in (15,):
                        return '\n'.join(lines)
                    if ch == 2:  # Ctrl+B toggle bold
                        toggle_markup('b')
                        redraw()
                        continue
                    if ch == 9:  # Ctrl+I toggle italic (note: Tab key conflicts; 9 is Tab; treat as Ctrl+I)
                        toggle_markup('i')
                        redraw()
                        continue
                    if ch == 21:  # Ctrl+U toggle underline
                        toggle_markup('u')
                        redraw()
                        continue
                    if ch == 20:  # Ctrl+T toggle strikethrough
                        toggle_markup('s')
                        redraw()
                        continue
                    # Search/Where Is: Ctrl+W (23). If no search pattern stored, prompt for one.
                    if ch == 23:
                        # Prompt for pattern using status bar input
                        curses.echo()
                        try:
                            stdscr.addstr(edit_h, 0, 'Search: '.ljust(max_x), curses.A_REVERSE)
                        except curses.error:
                            pass
                        stdscr.clrtoeol()
                        stdscr.refresh()
                        s = stdscr.getstr(edit_h, len('Search: ')).decode('utf-8', 'ignore')
                        curses.noecho()
                        if s:
                            search_pattern = s
                        # If there is a search pattern, find next occurrence
                        if search_pattern:
                            # Flatten lines to search sequentially
                            found = False
                            # Start search from current cursor position
                            start_line = cursor_y
                            start_col = cursor_x + 1
                            # Search current line from next col
                            if start_line < len(lines):
                                line = lines[start_line]
                                pos = line.lower().find(search_pattern.lower(), start_col)
                                if pos != -1:
                                    cursor_y = start_line
                                    cursor_x = pos
                                    found = True
                                else:
                                    # Search subsequent lines
                                    for y in range(start_line + 1, len(lines)):
                                        pos2 = lines[y].lower().find(search_pattern.lower())
                                        if pos2 != -1:
                                            cursor_y = y
                                            cursor_x = pos2
                                            found = True
                                            break
                            if not found:
                                # Wrap around
                                for y in range(0, start_line + 1):
                                    line = lines[y]
                                    pos2 = line.lower().find(search_pattern.lower())
                                    if pos2 != -1:
                                        cursor_y = y
                                        cursor_x = pos2
                                        found = True
                                        break
                            # Display message
                            msg = 'Found' if found else 'Not found'
                            try:
                                stdscr.addstr(edit_h, 0, msg[:max_x].ljust(max_x), curses.A_REVERSE)
                            except curses.error:
                                pass
                            stdscr.refresh()
                            curses.napms(1000)
                        redraw()
                        continue
                    # Replace: Ctrl+\ (28)
                    if ch == 28:
                        # Prompt for pattern and replacement
                        curses.echo()
                        try:
                            stdscr.addstr(edit_h, 0, 'Replace: '.ljust(max_x), curses.A_REVERSE)
                        except curses.error:
                            pass
                        stdscr.clrtoeol()
                        stdscr.refresh()
                        old = stdscr.getstr(edit_h, len('Replace: ')).decode('utf-8', 'ignore')
                        stdscr.addstr(edit_h, 0, 'With: '.ljust(max_x), curses.A_REVERSE)
                        stdscr.clrtoeol()
                        stdscr.refresh()
                        new = stdscr.getstr(edit_h, len('With: ')).decode('utf-8', 'ignore')
                        curses.noecho()
                        if old:
                            count = 0
                            for i in range(len(lines)):
                                if old in lines[i]:
                                    lines[i] = lines[i].replace(old, new)
                                    count += 1
                            msg = f'Replaced {count} occurrence(s)'
                        else:
                            msg = 'No pattern specified'
                        try:
                            stdscr.addstr(edit_h, 0, msg[:max_x].ljust(max_x), curses.A_REVERSE)
                        except curses.error:
                            pass
                        stdscr.refresh()
                        curses.napms(1000)
                        redraw()
                        continue
                    # Spell check: Ctrl+K (11)
                    if ch == 11:
                        do_spell_check()
                        redraw()
                        continue
                    if ch in (curses.KEY_IC,):  # Insert key toggles insert/overwrite
                        insert_mode = not insert_mode
                        redraw()
                        continue
                    if ch in (curses.KEY_LEFT,):
                        if cursor_x > 0:
                            cursor_x -= 1
                        elif cursor_y > 0:
                            cursor_y -= 1
                            cursor_x = len(lines[cursor_y])
                        redraw()
                        continue
                    if ch in (curses.KEY_RIGHT,):
                        line = lines[cursor_y] if cursor_y < len(lines) else ''
                        if cursor_x < len(line):
                            cursor_x += 1
                        elif cursor_y + 1 < len(lines):
                            cursor_y += 1
                            cursor_x = 0
                        redraw()
                        continue
                    if ch in (curses.KEY_UP,):
                        if cursor_y > 0:
                            cursor_y -= 1
                            cursor_x = min(cursor_x, len(lines[cursor_y]))
                        redraw()
                        continue
                    if ch in (curses.KEY_DOWN,):
                        if cursor_y + 1 < len(lines):
                            cursor_y += 1
                            cursor_x = min(cursor_x, len(lines[cursor_y]))
                        redraw()
                        continue
                    if ch in (curses.KEY_BACKSPACE, 127, 8):
                        # Backspace: delete character before cursor
                        if cursor_y < len(lines):
                            if cursor_x > 0:
                                line = lines[cursor_y]
                                lines[cursor_y] = line[:cursor_x - 1] + line[cursor_x:]
                                cursor_x -= 1
                            elif cursor_y > 0:
                                # Merge with previous line
                                prev_line = lines[cursor_y - 1]
                                line = lines[cursor_y]
                                new_x = len(prev_line)
                                lines[cursor_y - 1] = prev_line + line
                                lines.pop(cursor_y)
                                cursor_y -= 1
                                cursor_x = new_x
                        redraw()
                        continue
                    if ch in (curses.KEY_DC,):
                        # Delete key: delete character under cursor
                        if cursor_y < len(lines):
                            line = lines[cursor_y]
                            if cursor_x < len(line):
                                lines[cursor_y] = line[:cursor_x] + line[cursor_x + 1:]
                            elif cursor_y + 1 < len(lines):
                                # Merge next line into this line
                                next_line = lines[cursor_y + 1]
                                lines[cursor_y] = line + next_line
                                lines.pop(cursor_y + 1)
                        redraw()
                        continue
                    if ch in (10, 13):  # Enter key
                        insert_char('\n')
                        redraw()
                        continue
                    # Printable characters
                    if 32 <= ch <= 126:
                        insert_char(chr(ch))
                        # Ensure cursor stays within width
                        if cursor_x > edit_w - 1:
                            # Auto wrap to next line
                            insert_char('\n')
                        redraw()
                        continue
                    # Unknown keys are ignored
                return None

            # Start curses wrapper
            return curses.wrapper(editor)

        # Run editor in executor to avoid blocking event loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, run_editor)

    def load_preferences(self) -> None:
        """Load user preferences from the database into session attributes."""
        if not self.user:
            return
        prefs = self.server.db.get_user_preferences(self.user.id)
        # Editor preference
        self.pref_editor = prefs.get('editor', self.pref_editor)
        # Use ANSI preference: store as '1' or '0'
        if 'ansi' in prefs:
            self.use_ansi = prefs['ansi'] == '1'
        # Columns and rows
        if 'cols' in prefs:
            try:
                self.pref_cols = int(prefs['cols'])
            except ValueError:
                pass
        if 'rows' in prefs:
            try:
                self.pref_rows = int(prefs['rows'])
            except ValueError:
                pass
        # Fallback to defaults if not set
        if self.pref_cols == 0:
            try:
                self.pref_cols = int(CONFIG.get('defaults', 'cols', fallback=str(self.pref_cols)))
            except Exception:
                pass
        if self.pref_rows == 0:
            try:
                self.pref_rows = int(CONFIG.get('defaults', 'rows', fallback=str(self.pref_rows)))
            except Exception:
                pass
        # Thread view
        if 'thread_view' in prefs:
            self.pref_thread_view = prefs['thread_view'] == '1'
        # Signature inclusion
        if 'signature_include' in prefs:
            self.pref_signature_include = prefs['signature_include'] == '1'

        # Load timezone preference
        if 'timezone' in prefs:
            self.pref_timezone = prefs['timezone']
        else:
            # Default from configuration
            self.pref_timezone = CONFIG.get('defaults', 'timezone', fallback='UTC') if CONFIG else 'UTC'
        # Load time format preference (12h/24h)
        if 'time_format' in prefs:
            self.pref_time_format = prefs['time_format']
        else:
            self.pref_time_format = CONFIG.get('defaults', 'time_format', fallback='24h') if CONFIG else '24h'
        # Load language preference
        if 'language' in prefs:
            self.pref_language = prefs['language']
        else:
            self.pref_language = CONFIG.get('defaults', 'language', fallback='en') if CONFIG else 'en'

    def set_preference(self, key: str, value: str) -> None:
        """Persist a user preference to the database and update session state."""
        if not self.user:
            return
        self.server.db.set_user_preference(self.user.id, key, value)
        # Update session attribute as well
        if key == 'editor':
            self.pref_editor = value
        elif key == 'ansi':
            self.use_ansi = value == '1'
        elif key == 'cols':
            try:
                self.pref_cols = int(value)
            except ValueError:
                pass
        elif key == 'rows':
            try:
                self.pref_rows = int(value)
            except ValueError:
                pass
        elif key == 'thread_view':
            self.pref_thread_view = value == '1'
        elif key == 'signature_include':
            self.pref_signature_include = value == '1'

    # Chat room
    async def chat_room(self) -> None:
        """Enter the multi‑user chat room with IRC‑like commands and channels.

        Users begin in the #general channel. Commands start with '/'. Supported
        commands include:
        /quit or /part – leave the chat
        /join <channel> – join or create a channel
        /nick <name> – change your nickname
        /me <action> – send an emote
        /who – list users in the current channel
        /msg <user> <text> – send a private chat message to a user
        /help – show this help message

        Messages are persisted in the chat_messages table; the last N messages
        from the current channel are displayed on join. Channel names begin
        with '#'.
        """
        # Ensure nickname is set
        if not self.nickname:
            self.nickname = self.user.username if self.user else 'Guest'
        # Set default channel
        self.current_channel = '#general'
        # Ensure default channel exists in database
        chan = self.server.db.get_channel(self.current_channel)
        if chan is None:
            # Automatically create default channel if it doesn't exist
            self.server.db.add_channel(self.current_channel, description='General chat', min_level=0, min_age=0, link=False)
            chan = self.server.db.get_channel(self.current_channel)
        # Check ban on default channel
        if self.server.db.is_user_banned(self.user.id, chan['id']):  # type: ignore
            await self.send(ANSI_RED + "You are banned from chat." + ANSI_RESET + "\n")
            return
        # Mark as in chat
        self.in_chat = True
        # Load chat history
        history_lines = 20
        try:
            history_lines = int(CONFIG.get('defaults', 'chat_history_lines', fallback=str(history_lines))) if CONFIG else history_lines
        except Exception:
            pass
        msgs = self.server.db.list_chat_messages(self.current_channel, limit=history_lines)
        if msgs:
            for row in msgs:
                try:
                    ts = datetime.fromisoformat(row['created_at'])
                except Exception:
                    ts = datetime.utcnow()
                time_str = self.format_time(ts)
                msg_line = f"{ANSI_GREEN}[{time_str}] {row['nickname']}: {row['content']}{ANSI_RESET}\n"
                await self.send(msg_line)
        await self.send(ANSI_BOLD + ANSI_MAGENTA + f"\nYou have joined channel {self.current_channel}. Type '/help' for help.\n" + ANSI_RESET)
        try:
            while True:
                data = await self.reader.readline()
                if not data:
                    break
                text = data.decode('utf-8', 'ignore').rstrip('\r\n')
                if not text:
                    continue
                # Commands start with '/'
                if text.startswith('/'):
                    parts = text.split(' ', 1)
                    cmd = parts[0].lower()
                    arg = parts[1].strip() if len(parts) > 1 else ''
                    if cmd in ('/quit', '/part'):
                        # Exit chat
                        break
                    elif cmd == '/join':
                        # Join a channel
                        channel = arg.strip()
                        if not channel:
                            await self.send(ANSI_RED + "Usage: /join <channel>\n" + ANSI_RESET)
                            continue
                        if not channel.startswith('#'):
                            channel = '#' + channel
                        # Check if channel exists
                        chan = self.server.db.get_channel(channel)
                        if chan is None:
                            # Create channel only if user is global chat moderator or SysOp
                            if self.user and (self.user.level >= 255 or self.server.db.is_global_chat_moderator(self.user.id)):
                                self.server.db.add_channel(channel, description='', min_level=0, min_age=0, link=False)
                                chan = self.server.db.get_channel(channel)
                                # Broadcast creation message if link channel
                                # If channel is link flagged, enqueue creation for remote peers
                                # (Not implemented: remote propagation skeleton)
                                await self.send(ANSI_GREEN + f"Channel {channel} created.\n" + ANSI_RESET)
                            else:
                                await self.send(ANSI_RED + "Channel does not exist.\n" + ANSI_RESET)
                                continue
                        # Access checks
                        if not self.server.db.user_can_access_channel(chan['id'], self.user):  # type: ignore
                            await self.send(ANSI_RED + "You do not have access to this channel.\n" + ANSI_RESET)
                            continue
                        if self.server.db.is_user_banned(self.user.id, chan['id']):  # type: ignore
                            await self.send(ANSI_RED + "You are banned from this channel.\n" + ANSI_RESET)
                            continue
                        # Announce leaving
                        await self.send(ANSI_CYAN + f"Leaving {self.current_channel}.\n" + ANSI_RESET)
                        self.current_channel = channel
                        # Show history for new channel
                        msgs = self.server.db.list_chat_messages(self.current_channel, limit=history_lines)
                        for row in msgs:
                            try:
                                ts = datetime.fromisoformat(row['created_at'])
                            except Exception:
                                ts = datetime.utcnow()
                            time_str = self.format_time(ts)
                            msg_line = f"{ANSI_GREEN}[{time_str}] {row['nickname']}: {row['content']}{ANSI_RESET}\n"
                            await self.send(msg_line)
                        await self.send(ANSI_CYAN + f"Joined {self.current_channel}.\n" + ANSI_RESET)
                        continue
                    elif cmd == '/nick':
                        newnick = arg.strip()
                        if not newnick:
                            await self.send(ANSI_RED + "Usage: /nick <nickname>\n" + ANSI_RESET)
                            continue
                        self.nickname = newnick
                        await self.send(ANSI_CYAN + f"Nickname changed to {self.nickname}.\n" + ANSI_RESET)
                        continue
                    elif cmd == '/me':
                        action = arg
                        if not action:
                            await self.send(ANSI_RED + "Usage: /me <action>\n" + ANSI_RESET)
                            continue
                        ts = datetime.utcnow()
                        time_str = self.format_time(ts)
                        # Sanitize action text
                        action = sanitize_text(action)
                        content = f"* {self.nickname} {action}"
                        # Save to DB
                        self.server.db.add_chat_message(self.current_channel, self.user.id if self.user else 0, self.nickname, content)
                        formatted = f"{ANSI_GREEN}[{time_str}] {content}{ANSI_RESET}\n"
                        # Broadcast (including self) – send to all sessions in channel
                        await self.broadcast_chat(formatted, self.current_channel)
                        await self.send(formatted)
                        # If channel is linked, enqueue remote chat message
                        try:
                            # Determine if channel is configured as a link channel
                            if CONFIG and CONFIG.has_section('link_channels') and CONFIG.get('link_channels', self.current_channel, fallback=''):
                                payload = {
                                    'nickname': self.nickname,
                                    'content': content,
                                    'created_at': datetime.utcnow().isoformat(),
                                }
                                asyncio.create_task(self.server.sync_link_channel(self.current_channel, payload))
                        except Exception:
                            pass
                        continue
                    elif cmd == '/who':
                        # List users in current channel
                        users_in_channel = [sess.nickname or (sess.user.username if sess.user else 'Guest')
                                            for sess in self.server.sessions if sess.in_chat and sess.current_channel == self.current_channel]
                        await self.send(ANSI_CYAN + "Users in channel: " + ", ".join(users_in_channel) + "\n" + ANSI_RESET)
                        continue
                    elif cmd == '/msg':
                        # Private chat message to another user (only in chat)
                        if not arg:
                            await self.send(ANSI_RED + "Usage: /msg <user> <text>\n" + ANSI_RESET)
                            continue
                        # split first word as nickname and rest as message
                        try:
                            target_name, msg_text = arg.split(' ', 1)
                        except ValueError:
                            await self.send(ANSI_RED + "Usage: /msg <user> <text>\n" + ANSI_RESET)
                            continue
                        # Find session by nickname or username
                        target_session = None
                        for sess in self.server.sessions:
                            if sess.in_chat and (sess.nickname.lower() == target_name.lower() or (sess.user and sess.user.username.lower() == target_name.lower())):
                                target_session = sess
                                break
                        if not target_session:
                            await self.send(ANSI_RED + f"User {target_name} not found in chat.\n" + ANSI_RESET)
                            continue
                        ts = datetime.utcnow()
                        time_str = self.format_time(ts)
                        formatted = f"{ANSI_YELLOW}[{time_str}] (PM to {target_session.nickname}) {self.nickname}: {msg_text}{ANSI_RESET}\n"
                        await target_session.send(formatted)
                        await self.send(formatted)
                        continue
                    elif cmd == '/kick':
                        # Kick a user from the current channel (disconnect them)
                        if not arg:
                            await self.send(ANSI_RED + "Usage: /kick <user>\n" + ANSI_RESET)
                            continue
                        target = arg.strip()
                        # Check rights
                        if not self.user or not (self.user.level >= 255 or self.server.db.is_channel_moderator(self.server.db.get_channel(self.current_channel)['id'], self.user.id) or self.server.db.is_global_chat_moderator(self.user.id)):
                            await self.send(ANSI_RED + "You are not authorized to kick users.\n" + ANSI_RESET)
                            continue
                        # Find target session
                        t_sess = None
                        for sess in self.server.sessions:
                            if sess.in_chat and sess.current_channel == self.current_channel and (sess.nickname.lower() == target.lower() or (sess.user and sess.user.username.lower() == target.lower())):
                                t_sess = sess
                                break
                        if not t_sess:
                            await self.send(ANSI_RED + "User not found in channel.\n" + ANSI_RESET)
                            continue
                        # Disconnect target
                        await t_sess.send(ANSI_RED + "You have been kicked from the channel.\n" + ANSI_RESET)
                        t_sess.in_chat = False
                        await self.send(ANSI_GREEN + f"{target} has been kicked.\n" + ANSI_RESET)
                        continue
                    elif cmd in ('/mute', '/ban', '/unmute', '/unban'):
                        # Mute/ban/unmute/unban commands
                        parts2 = arg.split()
                        if not parts2:
                            await self.send(ANSI_RED + f"Usage: {cmd} <user> [duration]\n" + ANSI_RESET)
                            continue
                        target_name = parts2[0]
                        duration_str = parts2[1] if len(parts2) > 1 else ''
                        # Check rights
                        if not self.user or not (self.user.level >= 255 or self.server.db.is_channel_moderator(self.server.db.get_channel(self.current_channel)['id'], self.user.id) or self.server.db.is_global_chat_moderator(self.user.id)):
                            await self.send(ANSI_RED + "You are not authorized to perform this action.\n" + ANSI_RESET)
                            continue
                        # Find target user
                        target_user = None
                        target_sess = None
                        for sess in self.server.sessions:
                            if sess.user and (sess.user.username.lower() == target_name.lower() or sess.nickname.lower() == target_name.lower()):
                                target_user = sess.user
                                target_sess = sess
                                break
                        if not target_user:
                            # Check DB for user existence
                            u_row = self.server.db.get_user(target_name)
                            if u_row:
                                target_user = User(id=u_row['id'], username=u_row['username'], level=u_row['level'])
                        if not target_user:
                            await self.send(ANSI_RED + "User not found.\n" + ANSI_RESET)
                            continue
                        # Parse duration
                        expires_at = None
                        if duration_str:
                            try:
                                num_part = ''
                                unit = ''
                                for ch in duration_str:
                                    if ch.isdigit():
                                        num_part += ch
                                    else:
                                        unit += ch
                                amount = int(num_part) if num_part else 0
                                if amount == 0:
                                    expires_at = None
                                else:
                                    # Determine unit multiplier
                                    if not unit:
                                        unit = 'm'
                                    unit = unit.lower()
                                    seconds = 0
                                    if unit == 's':
                                        seconds = amount
                                    elif unit == 'm':
                                        seconds = amount * 60
                                    elif unit == 'h':
                                        seconds = amount * 3600
                                    elif unit == 'd':
                                        seconds = amount * 86400
                                    elif unit == 'w':
                                        seconds = amount * 604800
                                    elif unit == 'y':
                                        seconds = amount * 31536000
                                    else:
                                        seconds = amount * 60
                                    expires_at = (datetime.utcnow() + timedelta(seconds=seconds)).isoformat()
                            except Exception:
                                expires_at = None
                        chan_row = self.server.db.get_channel(self.current_channel)
                        chan_id = chan_row['id'] if chan_row else None
                        if cmd == '/mute':
                            self.server.db.mute_user(target_user.id, chan_id, expires_at, self.user.id)  # type: ignore
                            msg = f"{target_user.username} has been muted"
                        elif cmd == '/ban':
                            self.server.db.ban_user(target_user.id, chan_id, expires_at, self.user.id)  # type: ignore
                            msg = f"{target_user.username} has been banned"
                        elif cmd == '/unmute':
                            self.server.db.unmute_user(target_user.id, chan_id)  # type: ignore
                            msg = f"{target_user.username} has been unmuted"
                        elif cmd == '/unban':
                            self.server.db.unban_user(target_user.id, chan_id)  # type: ignore
                            msg = f"{target_user.username} has been unbanned"
                        # Log moderation action
                        self.server.db.conn.execute('INSERT INTO moderation_log (moderator_id, target_type, target_id, action, info, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                                                    (self.user.id if self.user else 0, 'channel', chan_id if chan_id else 0, cmd.strip('/'), msg, datetime.utcnow().isoformat()))
                        self.server.db.conn.commit()
                        # Broadcast to channel
                        notif = ANSI_YELLOW + msg + (f" until {expires_at}" if expires_at else '') + ANSI_RESET + "\n"
                        await self.broadcast_chat(notif, self.current_channel)
                        await self.send(notif)
                        continue
                    elif cmd == '/help':
                        help_lines = [
                            "Chat commands:",
                            "/quit or /part – leave the chat", 
                            "/join <channel> – join or create a channel", 
                            "/nick <name> – change your nickname", 
                            "/me <action> – send an action", 
                            "/who – list users in current channel", 
                            "/msg <user> <text> – send a private chat message", 
                            "/kick <user> – remove a user from the channel (mods only)",
                            "/mute /ban <user> [duration] – mute or ban a user (mods only)",
                            "/unmute /unban <user> – lift sanctions (mods only)",
                            "/help – show this message",
                        ]
                        await self.send(ANSI_CYAN + "\n" + "\n".join(help_lines) + "\n" + ANSI_RESET)
                        continue
                    else:
                        await self.send(ANSI_RED + "Unknown command. Type '/help' for help.\n" + ANSI_RESET)
                        continue
                # Normal message
                # Check if muted
                chan_row = self.server.db.get_channel(self.current_channel)
                chan_id = chan_row['id'] if chan_row else None
                if self.user and self.server.db.is_user_muted(self.user.id, chan_id):  # type: ignore
                    await self.send(ANSI_RED + "You are muted and cannot speak in this channel.\n" + ANSI_RESET)
                    continue
                ts = datetime.utcnow()
                time_str = self.format_time(ts)
                # Sanitize normal message
                clean_text = sanitize_text(text)
                # Persist message
                self.server.db.add_chat_message(self.current_channel, self.user.id if self.user else 0, self.nickname, clean_text)
                formatted = f"{ANSI_GREEN}[{time_str}] {self.nickname}: {clean_text}{ANSI_RESET}\n"
                # Broadcast to others
                await self.broadcast_chat(formatted, self.current_channel)
                # Echo to self
                await self.send(formatted)
                # Queue message for linked channels
                try:
                    if CONFIG and CONFIG.has_section('link_channels') and CONFIG.get('link_channels', self.current_channel, fallback=''):
                        payload = {
                            'nickname': self.nickname,
                            'content': text,
                            'created_at': datetime.utcnow().isoformat(),
                        }
                        asyncio.create_task(self.server.sync_link_channel(self.current_channel, payload))
                except Exception:
                    pass
        finally:
            # Leave chat room
            self.in_chat = False
            await self.send(ANSI_CYAN + f"Leaving chat room.\n" + ANSI_RESET)

    # Door games (external programs)
    async def door_games_menu(self) -> None:
        # Define a simple list of games; in practice these would be external
        # executables or scripts. For demonstration we provide a couple of
        # built‑in games: Fortune (prints a random fortune) and Echo (simple echo).
        games = {
            '1': ('Fortune', self.game_fortune),
            '2': ('Echo', self.game_echo),
        }
        while True:
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nDoor Games:\n" + ANSI_RESET]
            for key, (name, _) in games.items():
                lines.append(f"{key}) {name}")
            lines.append("0) Back to Main Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            if choice in games:
                name, func = games[choice]
                await func()
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def game_fortune(self) -> None:
        """Display a random fortune (using the 'fortune' command if available)."""
        await self.send(ANSI_CYAN + "\n--- Fortune ---\n" + ANSI_RESET)
        # Try to run the fortune command; fallback to an internal fortune
        try:
            proc = await asyncio.create_subprocess_exec('fortune', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            text = stdout.decode('utf-8', 'ignore') if stdout else "No fortune today."
        except FileNotFoundError:
            text = "Fortune command not available. Here's a free quote:\n" \
                   "The only way to get rid of temptation is to yield to it. — Oscar Wilde"
        await self.send(text + "\n")

    async def game_echo(self) -> None:
        """Simple echo game that repeats the user's input."""
        await self.send(ANSI_CYAN + "\nType something and I'll echo it back (type '/quit' to return).\n" + ANSI_RESET)
        while True:
            data = await self.reader.readline()
            if not data:
                return
            text = data.decode('utf-8', 'ignore').rstrip('\r\n')
            if text == '/quit':
                return
            await self.send(f"You said: {text}\n")

    # User settings
    async def user_settings_menu(self) -> None:
        while True:
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nUser Settings\n" + ANSI_RESET]
            lines.append("1) Change password")
            lines.append("2) Preferences")
            lines.append("3) Edit profile answers")
            lines.append("4) Edit signature")
            lines.append("0) Back to Main Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice == '1':
                await self.change_password()
            elif choice == '2':
                await self.preferences_menu()
            elif choice == '3':
                await self.user_edit_profile()
            elif choice == '4':
                await self.user_edit_signature()
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def change_password(self) -> None:
        await self.send(ANSI_CYAN + "Enter current password: " + ANSI_RESET)
        old = await self.reader.readline()
        if not old:
            return
        old_pwd = old.decode('utf-8', 'ignore').strip()
        # Verify
        user_row = self.server.db.get_user(self.user.username)  # type: ignore
        if not verify_password(old_pwd, user_row['password']):
            await self.send(ANSI_RED + "Incorrect password.\n" + ANSI_RESET)
            return
        await self.send(ANSI_CYAN + "Enter new password: " + ANSI_RESET)
        new1 = await self.reader.readline()
        if not new1:
            return
        new_pwd1 = new1.decode('utf-8', 'ignore').strip()
        await self.send(ANSI_CYAN + "Confirm new password: " + ANSI_RESET)
        new2 = await self.reader.readline()
        if not new2:
            return
        new_pwd2 = new2.decode('utf-8', 'ignore').strip()
        if new_pwd1 != new_pwd2:
            await self.send(ANSI_RED + "Passwords do not match.\n" + ANSI_RESET)
            return
        hashed = hash_password(new_pwd1)
        self.server.db.conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, self.user.id))  # type: ignore
        self.server.db.conn.commit()
        await self.send(ANSI_GREEN + "Password changed successfully.\n" + ANSI_RESET)

    async def logoff_wall_message(self) -> None:
        """Prompt the user to leave a quick wall message before logging off."""
        # Ask for recipient (optional)
        await self.send(ANSI_CYAN + "Enter recipient username (leave blank for public): " + ANSI_RESET)
        data = await self.reader.readline()
        if not data:
            return
        to_user = data.decode('utf-8', 'ignore').strip()
        to_id: Optional[int] = None
        if to_user:
            u_row = self.server.db.get_user(to_user)
            if not u_row:
                await self.send(ANSI_RED + "User not found. Skipping wall post.\n" + ANSI_RESET)
                return
            to_id = u_row['id']
        await self.send(ANSI_CYAN + "Enter your message (single line): " + ANSI_RESET)
        msg_data = await self.reader.readline()
        if not msg_data:
            return
        msg = msg_data.decode('utf-8', 'ignore').strip()
        if msg:
            self.server.db.post_wall_message(self.user.id, to_id, msg)  # type: ignore
            await self.send(ANSI_GREEN + "Message posted.\n" + ANSI_RESET)

    async def preferences_menu(self) -> None:
        """Allow the user to customize their BBS experience."""
        while True:
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nPreferences\n" + ANSI_RESET]
            # Show current settings
            lines.append(f"1) ANSI colors: {'On' if self.use_ansi else 'Off'}")
            lines.append(f"2) Editor: {'Fullscreen' if self.pref_editor == 'full' else 'Line'}")
            lines.append(f"3) Columns (wrap width): {self.pref_cols if self.pref_cols else 'Default'}")
            lines.append(f"4) Rows (page height): {self.pref_rows if self.pref_rows else 'Default'}")
            lines.append(f"5) Thread view: {'On' if self.pref_thread_view else 'Off'}")
            lines.append(f"6) Include signature: {'Yes' if self.pref_signature_include else 'No'}")
            lines.append(f"7) Timezone: {self.pref_timezone}")
            lines.append(f"8) Time format: {self.pref_time_format}")
            lines.append(f"9) Language: {self.pref_language}")
            lines.append("0) Back")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice == '1':
                # Toggle ANSI
                self.use_ansi = not self.use_ansi
                self.set_preference('ansi', '1' if self.use_ansi else '0')
                await self.send(ANSI_GREEN + f"ANSI colors {'enabled' if self.use_ansi else 'disabled'}.\n" + ANSI_RESET)
            elif choice == '2':
                # Toggle editor
                self.pref_editor = 'full' if self.pref_editor == 'line' else 'line'
                self.set_preference('editor', self.pref_editor)
                await self.send(ANSI_GREEN + f"Editor set to {'Fullscreen' if self.pref_editor == 'full' else 'Line'}.\n" + ANSI_RESET)
            elif choice == '3':
                await self.send(ANSI_CYAN + "Enter preferred column width (0 for default): " + ANSI_RESET)
                data = await self.reader.readline()
                if not data:
                    continue
                try:
                    cols = int(data.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid number.\n" + ANSI_RESET)
                    continue
                self.pref_cols = cols if cols > 0 else 0
                self.set_preference('cols', str(self.pref_cols))
                await self.send(ANSI_GREEN + "Column width updated.\n" + ANSI_RESET)
            elif choice == '4':
                await self.send(ANSI_CYAN + "Enter preferred row count (0 for default): " + ANSI_RESET)
                data = await self.reader.readline()
                if not data:
                    continue
                try:
                    rows = int(data.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid number.\n" + ANSI_RESET)
                    continue
                self.pref_rows = rows if rows > 0 else 0
                self.set_preference('rows', str(self.pref_rows))
                await self.send(ANSI_GREEN + "Row count updated.\n" + ANSI_RESET)
            elif choice == '5':
                # Toggle thread view
                self.pref_thread_view = not self.pref_thread_view
                self.set_preference('thread_view', '1' if self.pref_thread_view else '0')
                await self.send(ANSI_GREEN + f"Thread view {'enabled' if self.pref_thread_view else 'disabled'}.\n" + ANSI_RESET)
            elif choice == '6':
                # Toggle signature include
                self.pref_signature_include = not self.pref_signature_include
                self.set_preference('signature_include', '1' if self.pref_signature_include else '0')
                await self.send(ANSI_GREEN + f"Signature will {'now' if self.pref_signature_include else 'no longer'} be included by default.\n" + ANSI_RESET)
            elif choice == '7':
                # Change timezone
                await self.send(ANSI_CYAN + "Enter timezone (e.g. UTC, Europe/Berlin): " + ANSI_RESET)
                data = await self.reader.readline()
                if data:
                    tz = data.decode('utf-8', 'ignore').strip()
                    if tz:
                        self.pref_timezone = tz
                        self.set_preference('timezone', tz)
                        await self.send(ANSI_GREEN + "Timezone updated.\n" + ANSI_RESET)
            elif choice == '8':
                # Change time format
                await self.send(ANSI_CYAN + "Enter time format (12h or 24h): " + ANSI_RESET)
                data = await self.reader.readline()
                if data:
                    fmt = data.decode('utf-8', 'ignore').strip().lower()
                    if fmt in ('12h', '24h', '12', '24'):
                        # Normalize
                        fmt_norm = '12h' if fmt.startswith('12') else '24h'
                        self.pref_time_format = fmt_norm
                        self.set_preference('time_format', fmt_norm)
                        await self.send(ANSI_GREEN + "Time format updated.\n" + ANSI_RESET)
                    else:
                        await self.send(ANSI_RED + "Invalid format. Use 12h or 24h.\n" + ANSI_RESET)
            elif choice == '9':
                # Change language (for future use)
                await self.send(ANSI_CYAN + "Enter language code (e.g. en, de): " + ANSI_RESET)
                data = await self.reader.readline()
                if data:
                    lang = data.decode('utf-8', 'ignore').strip().lower()
                    if lang:
                        self.pref_language = lang
                        self.set_preference('language', lang)
                        await self.send(ANSI_GREEN + "Language preference updated.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def user_edit_profile(self) -> None:
        """Allow the user to update their answers to editable registration questions."""
        if not CONFIG or not CONFIG.has_section('questions'):
            await self.send(ANSI_RED + "No registration questions configured.\n" + ANSI_RESET)
            return
        # Determine which fields are editable by user
        editable_cfg = None
        if CONFIG.has_section('questions_editable'):
            editable_cfg = CONFIG['questions_editable']
        profile = self.server.db.get_user_profile(self.user.id)  # type: ignore
        q_types = CONFIG['question_types'] if CONFIG.has_section('question_types') else {}
        q_formats = CONFIG['question_formats'] if CONFIG.has_section('question_formats') else {}
        for field, prompt in CONFIG['questions'].items():
            # Skip if not editable
            if editable_cfg is not None and editable_cfg.get(field, 'true').lower() != 'true':
                continue
            current_value = profile.get(field, '')
            await self.send(ANSI_CYAN + f"{prompt} (current: {current_value}) - leave blank to keep: " + ANSI_RESET)
            data = await self.reader.readline()
            if not data:
                continue
            new_val = data.decode('utf-8', 'ignore').strip()
            if new_val:
                q_type = q_types.get(field, 'text').lower()
                if q_type == 'date':
                    fmt = q_formats.get(field, '%Y-%m-%d')
                    try:
                        dt = datetime.strptime(new_val, fmt)
                        value_to_store = dt.strftime('%Y-%m-%d')
                    except Exception:
                        await self.send(ANSI_RED + f"Invalid date format. Expected {fmt}. Skipping.\n" + ANSI_RESET)
                        continue
                elif q_type == 'number':
                    if not new_val.isdigit():
                        await self.send(ANSI_RED + "Please enter digits only. Skipping.\n" + ANSI_RESET)
                        continue
                    value_to_store = new_val
                elif q_type == 'email':
                    # Simple email validation
                    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', new_val):
                        await self.send(ANSI_RED + "Invalid email address. Skipping.\n" + ANSI_RESET)
                        continue
                    value_to_store = new_val
                else:
                    value_to_store = new_val
                self.server.db.set_user_profile(self.user.id, field, value_to_store)
        await self.send(ANSI_GREEN + "Profile updated.\n" + ANSI_RESET)

    async def user_edit_signature(self) -> None:
        """Allow the user to create or edit their signature using their preferred editor."""
        # Load existing signature
        sig = self.server.db.get_user_signature(self.user.id)  # type: ignore
        initial = sig if sig else ''
        # Use chosen editor
        text = await self.edit_message() if self.pref_editor != 'full' else await self.fullscreen_editor(initial)
        if text is None:
            await self.send(ANSI_YELLOW + "Signature edit cancelled.\n" + ANSI_RESET)
            return
        self.server.db.set_user_signature(self.user.id, text)  # type: ignore
        await self.send(ANSI_GREEN + "Signature saved.\n" + ANSI_RESET)

    async def ask_profile_questions(self) -> None:
        """Ask registration questions defined in the configuration and store the answers."""
        if not self.user:
            return
        if not CONFIG or not CONFIG.has_section('questions'):
            return
        q_types = CONFIG['question_types'] if CONFIG.has_section('question_types') else {}
        q_formats = CONFIG['question_formats'] if CONFIG.has_section('question_formats') else {}
        for field, prompt in CONFIG['questions'].items():
            await self.send(ANSI_CYAN + f"{prompt}: " + ANSI_RESET)
            data = await self.reader.readline()
            if not data:
                continue
            value = data.decode('utf-8', 'ignore').strip()
            # Validate according to type
            q_type = q_types.get(field, 'text').lower()
            if q_type == 'date' and value:
                fmt = q_formats.get(field, '%Y-%m-%d')
                try:
                    dt = datetime.strptime(value, fmt)
                    value_to_store = dt.strftime('%Y-%m-%d')
                except Exception:
                    await self.send(ANSI_RED + f"Invalid date format. Expected {fmt}. Skipping.\n" + ANSI_RESET)
                    continue
            elif q_type == 'number' and value:
                if not value.isdigit():
                    await self.send(ANSI_RED + "Please enter digits only. Skipping.\n" + ANSI_RESET)
                    continue
                value_to_store = value
            elif q_type == 'email' and value:
                if not re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
                    await self.send(ANSI_RED + "Invalid email address. Skipping.\n" + ANSI_RESET)
                    continue
                value_to_store = value
            else:
                value_to_store = value
            self.server.db.set_user_profile(self.user.id, field, value_to_store)

    # Private messaging
    async def pm_menu(self) -> None:
        """Display and handle the private messaging menu."""
        while True:
            messages = self.server.db.list_private_messages(self.user.id)  # type: ignore
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nPrivate Messages\n" + ANSI_RESET]
            if messages:
                for m in messages:
                    status = 'Unread' if not m['read'] else 'Read'
                    created = m['created_at'][:19].replace('T', ' ')
                    lines.append(f"{m['id']}) {status} from {m['from_user']} - {m['subject']} ({created})")
            else:
                lines.append("No messages.")
            lines.append("n) New message")
            lines.append("s) Sent messages")
            lines.append("0) Back to Main Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice.lower() == 'n':
                await self.pm_send_message()
            elif choice.lower() == 's':
                await self.pm_sent_messages_menu()
            else:
                try:
                    msg_id = int(choice)
                except ValueError:
                    await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                    continue
                await self.pm_view_message(msg_id)

    async def pm_view_message(self, msg_id: int) -> None:
        msg = self.server.db.get_private_message(msg_id, self.user.id)  # type: ignore
        if not msg:
            await self.send(ANSI_RED + "Message not found.\n" + ANSI_RESET)
            return
        # Mark as read
        if not msg['read']:
            self.server.db.mark_private_message_read(msg_id)
        lines = [ANSI_CYAN + f"\nFrom: {msg['from_user']}\nSubject: {msg['subject']}\nDate: {msg['created_at'][:19].replace('T',' ')}\n" + ANSI_RESET]
        lines.append(msg['content'])
        lines.append("\nOptions: r) Reply, d) Delete, 0) Back")
        await self.send("\n".join(lines) + "\n")
        choice = await self.prompt()
        if choice == '0':
            return
        elif choice.lower() == 'd':
            self.server.db.delete_private_message(msg_id, self.user.id)  # type: ignore
            await self.send(ANSI_GREEN + "Message deleted.\n" + ANSI_RESET)
        elif choice.lower() == 'r':
            await self.pm_send_message(to_username=msg['from_user'], default_subject=f"Re: {msg['subject']}")

    async def pm_sent_messages_menu(self) -> None:
        """List and allow the user to view messages they have sent."""
        messages = self.server.db.list_sent_private_messages(self.user.id)  # type: ignore
        while True:
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nSent Messages\n" + ANSI_RESET]
            if messages:
                for m in messages:
                    # Determine read status
                    status = 'Read' if m['read'] and m['receipt_visible'] else ('Unread' if not m['read'] else 'Unknown')
                    created = m['created_at'][:19].replace('T', ' ')
                    lines.append(f"{m['id']}) To {m['to_user']} - {m['subject']} ({status}, {created})")
            else:
                lines.append("No sent messages.")
            lines.append("0) Back")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            try:
                msg_id = int(choice)
            except ValueError:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                continue
            msg = None
            for m in messages:
                if m['id'] == msg_id:
                    msg = m
                    break
            if not msg:
                await self.send(ANSI_RED + "Message not found.\n" + ANSI_RESET)
                continue
            # Display message details
            lines = [ANSI_CYAN + f"\nTo: {msg['to_user']}\nSubject: {msg['subject']}\nDate: {msg['created_at'][:19].replace('T',' ')}\n" + ANSI_RESET]
            lines.append(msg['content'])
            lines.append("\nPress Enter to return.")
            await self.send("\n".join(lines) + "\n")
            # Wait for Enter
            await self.reader.readline()

    async def pm_send_message(self, to_username: Optional[str] = None, default_subject: Optional[str] = None) -> None:
        # Determine recipient
        if not to_username:
            await self.send(ANSI_CYAN + "Enter recipient username: " + ANSI_RESET)
            data = await self.reader.readline()
            if not data:
                return
            to_username = data.decode('utf-8', 'ignore').strip()
        # Check for remote address (user@host)
        if '@' in to_username:
            local_part, host = to_username.split('@', 1)
            # Compose subject
            if default_subject:
                subject = default_subject
            else:
                await self.send(ANSI_CYAN + "Enter subject: " + ANSI_RESET)
                subj_line = await self.safe_readline()
                if subj_line is None:
                    return
                subject = subj_line.strip()
            # Compose content via editor
            content = await self.edit_message()
            if content is None:
                await self.send(ANSI_YELLOW + "Message cancelled.\n" + ANSI_RESET)
                return
            # Append signature if enabled
            if self.pref_signature_include:
                sig = self.server.db.get_user_signature(self.user.id)  # type: ignore
                if sig:
                    content = content + "\n--\n" + sig
            # Send via remote PM system
            # Sanitize before sending
            subject_clean = sanitize_text(subject)
            content_clean = sanitize_text(content)
            ok = await self.server.send_remote_pm(self.user, local_part, host, subject_clean, content_clean)
            if ok:
                await self.send(ANSI_GREEN + "Remote message queued/sent.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Failed to send remote message.\n" + ANSI_RESET)
            return
        # Local user lookup
        u_row = self.server.db.get_user(to_username)
        if not u_row:
            await self.send(ANSI_RED + "User not found.\n" + ANSI_RESET)
            return
        # Subject
        if default_subject:
            subject = default_subject
        else:
            await self.send(ANSI_CYAN + "Enter subject: " + ANSI_RESET)
            subj_line = await self.safe_readline()
            if subj_line is None:
                return
            subject = subj_line.strip()
        # Compose message
        content = await self.edit_message()
        if content is None:
            await self.send(ANSI_YELLOW + "Message cancelled.\n" + ANSI_RESET)
            return
        # Append signature if user preference
        if self.pref_signature_include:
            sig = self.server.db.get_user_signature(self.user.id)  # type: ignore
            if sig:
                content = content + "\n--\n" + sig
        # Sanitize subject and content before storing
        subject_clean = sanitize_text(subject)
        content_clean = sanitize_text(content)
        self.server.db.add_private_message(self.user.id, u_row['id'], subject_clean, content_clean)  # type: ignore
        await self.send(ANSI_GREEN + "Message sent.\n" + ANSI_RESET)

    async def thread_view_sequential(self, board_id: int, thread_id: int) -> None:
        """Sequential message viewer for a thread. Shows posts one by one with navigation."""
        posts = self.server.db.list_posts(thread_id)
        if not posts:
            await self.send(ANSI_YELLOW + "No posts in this thread.\n" + ANSI_RESET)
            return
        index = 0
        while True:
            p = posts[index]
            created = p['created_at'][:19].replace('T', ' ')
            lines = [ANSI_BOLD + ANSI_CYAN + f"\nPost {index+1} of {len(posts)}\n" + ANSI_RESET]
            lines.append(f"From: {p['author']} at {created}\n")
            # Append attachments list if present
            content = p['content']
            att_rows = self.server.db.list_attachments(p['id'])  # type: ignore
            attach_info = ''
            if att_rows:
                names = [att['filename'] for att in att_rows]
                attach_info = "\nAttachments: " + ", ".join(names)
            lines.append(content + attach_info + "\n")
            lines.append("Options: n) Next, p) Previous, r) Reply, 0) Back")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice.lower() == 'n':
                if index + 1 < len(posts):
                    index += 1
                else:
                    await self.send(ANSI_YELLOW + "No further posts.\n" + ANSI_RESET)
            elif choice.lower() == 'p':
                if index > 0:
                    index -= 1
                else:
                    await self.send(ANSI_YELLOW + "This is the first post.\n" + ANSI_RESET)
            elif choice.lower() == 'r':
                content = await self.edit_message()
                if content is None:
                    await self.send(ANSI_YELLOW + "Reply cancelled.\n" + ANSI_RESET)
                else:
                    # Append signature if user preference
                    if self.pref_signature_include:
                        sig = self.server.db.get_user_signature(self.user.id)  # type: ignore
                        if sig:
                            content = content + "\n--\n" + sig
                    # Add post and optionally upload attachment
                    new_post_id = self.server.db.add_post(thread_id, self.user.id, content)  # type: ignore
                    # Ask for attachment
                    try:
                        await self.send(ANSI_CYAN + "Attach a file to this post via ZModem? (y/n): " + ANSI_RESET)
                        attach_resp = await self.reader.readline()
                        if attach_resp and attach_resp.decode('utf-8', 'ignore').strip().lower().startswith('y'):
                            await self.zmodem_receive_attachment(new_post_id)
                    except Exception:
                        pass
                    posts = self.server.db.list_posts(thread_id)  # reload
                    index = len(posts) - 1
                    await self.send(ANSI_GREEN + "Message posted.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Invalid option.\n" + ANSI_RESET)

    # SysOp console
    async def sysop_menu(self) -> None:
        while True:
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nSysOp Console\n" + ANSI_RESET]
            lines.append("1) List users")
            lines.append("2) Promote/Demote user")
            lines.append("3) Delete user")
            lines.append("4) Create board")
            lines.append("5) Manage boards")
            lines.append("6) Manage user levels")
            lines.append("7) Manage registration questions")
            # Show PM review option only if SysOp PM access is enabled
            allow_pm = True
            if CONFIG and CONFIG.has_option('defaults', 'sysop_pm_access'):
                allow_pm = CONFIG.get('defaults', 'sysop_pm_access').lower() == 'true'
            if allow_pm:
                lines.append("8) Review private messages")
            lines.append("9) Check for updates")
            # If there are pending handshake requests, offer an approval option
            if self.server.pending_handshakes:
                lines.append("10) Approve pending handshakes")
            lines.append("0) Back to Main Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            elif choice == '1':
                await self.sysop_list_users()
            elif choice == '2':
                await self.sysop_promote_user()
            elif choice == '3':
                await self.sysop_delete_user()
            elif choice == '4':
                await self.sysop_create_board()
            elif choice == '5':
                await self.sysop_manage_boards()
            elif choice == '6':
                await self.sysop_manage_levels()
            elif choice == '7':
                await self.sysop_manage_questions()
            elif choice == '8':
                # Only allow if enabled
                allow_pm = True
                if CONFIG and CONFIG.has_option('defaults', 'sysop_pm_access'):
                    allow_pm = CONFIG.get('defaults', 'sysop_pm_access').lower() == 'true'
                if allow_pm:
                    await self.sysop_review_pms()
                else:
                    await self.send(ANSI_RED + "PM review is disabled.\n" + ANSI_RESET)
            elif choice == '9':
                await self.sysop_check_update()
            elif choice == '10' and self.server.pending_handshakes:
                await self.sysop_manage_handshakes()
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def sysop_list_users(self) -> None:
        users = self.server.db.list_users()
        lines = [ANSI_BOLD + ANSI_MAGENTA + "\nUser List\n" + ANSI_RESET]
        for u in users:
            lines.append(f"{u['id']}) {u['username']} (Level {u['level']}, created {u['created_at'][:19].replace('T',' ')})")
        await self.send("\n".join(lines) + "\n")

    async def sysop_promote_user(self) -> None:
        await self.sysop_list_users()
        await self.send(ANSI_CYAN + "Enter user ID to change level: " + ANSI_RESET)
        data = await self.reader.readline()
        if not data:
            return
        try:
            uid = int(data.decode('utf-8', 'ignore').strip())
        except ValueError:
            await self.send(ANSI_RED + "Invalid user ID.\n" + ANSI_RESET)
            return
        u = self.server.db.conn.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
        if not u:
            await self.send(ANSI_RED + "User not found.\n" + ANSI_RESET)
            return
        await self.send(ANSI_CYAN + f"Current level: {u['level']}. Enter new level (0=user, 10=sysop): " + ANSI_RESET)
        level_data = await self.reader.readline()
        if not level_data:
            return
        try:
            new_level = int(level_data.decode('utf-8', 'ignore').strip())
        except ValueError:
            await self.send(ANSI_RED + "Invalid level.\n" + ANSI_RESET)
            return
        self.server.db.set_user_level(uid, new_level)
        await self.send(ANSI_GREEN + "User level updated.\n" + ANSI_RESET)

    async def sysop_delete_user(self) -> None:
        await self.sysop_list_users()
        await self.send(ANSI_CYAN + "Enter user ID to delete: " + ANSI_RESET)
        data = await self.reader.readline()
        if not data:
            return
        try:
            uid = int(data.decode('utf-8', 'ignore').strip())
        except ValueError:
            await self.send(ANSI_RED + "Invalid user ID.\n" + ANSI_RESET)
            return
        self.server.db.delete_user(uid)
        await self.send(ANSI_GREEN + "User deleted.\n" + ANSI_RESET)

    async def sysop_manage_boards(self) -> None:
        """SysOp function to modify board access settings and min levels."""
        while True:
            # Display boards summary
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nBoards Management\n" + ANSI_RESET]
            msg_boards = self.server.db.list_boards()
            file_areas = self.server.db.list_file_areas()
            lines.append("Message Boards:")
            for b in msg_boards:
                lines.append(f"  M{b['id']}) {b['name']} (MinLvl {b['min_level']})")
            lines.append("File Areas:")
            for b in file_areas:
                lines.append(f"  F{b['id']}) {b['name']} (MinLvl {b['min_level']})")
            lines.append("0) Back to SysOp Menu")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            if not choice:
                continue
            # Determine board type and id
            kind = choice[0].upper()
            try:
                b_id = int(choice[1:])
            except (ValueError, IndexError):
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                continue
            board_row = None
            board_type = None
            if kind == 'M':
                board_type = 'msg'
                for b in msg_boards:
                    if b['id'] == b_id:
                        board_row = b
                        break
            elif kind == 'F':
                board_type = 'file'
                for b in file_areas:
                    if b['id'] == b_id:
                        board_row = b
                        break
            if board_row is None or board_type is None:
                await self.send(ANSI_RED + "Board not found.\n" + ANSI_RESET)
                continue
            # Board action menu
            while True:
                await self.send(ANSI_CYAN + f"\nSelected board: {board_row['name']} (type {board_type}, min level {board_row['min_level']}, min age {board_row['min_age']})\n" + ANSI_RESET)
                await self.send("1) Set minimum level\n2) Grant user access\n3) Revoke user access\n4) Set minimum age\n0) Back\n")
                sub = await self.prompt()
                if sub == '0':
                    break
                elif sub == '1':
                    # List available levels
                    level_entries = []
                    if CONFIG and CONFIG.has_section('levels'):
                        for lev, label in CONFIG['levels'].items():
                            level_entries.append(f"{lev} ({label})")
                    else:
                        level_entries.append("0 (Guest)")
                    await self.send(ANSI_CYAN + "Available levels: " + ", ".join(level_entries) + "\n" + ANSI_RESET)
                    await self.send(ANSI_CYAN + "Enter new minimum level: " + ANSI_RESET)
                    lvl_data = await self.reader.readline()
                    if not lvl_data:
                        continue
                    try:
                        new_lvl = int(lvl_data.decode('utf-8', 'ignore').strip())
                    except ValueError:
                        await self.send(ANSI_RED + "Invalid level.\n" + ANSI_RESET)
                        continue
                    if board_type == 'msg':
                        self.server.db.conn.execute('UPDATE boards SET min_level = ? WHERE id = ?', (new_lvl, b_id))
                    else:
                        # File areas
                        self.server.db.conn.execute('UPDATE file_areas SET min_level = ? WHERE id = ?', (new_lvl, b_id))
                    self.server.db.conn.commit()
                    board_row['min_level'] = new_lvl
                    await self.send(ANSI_GREEN + "Minimum level updated.\n" + ANSI_RESET)
                elif sub == '2':
                    await self.send(ANSI_CYAN + "Enter username to grant access: " + ANSI_RESET)
                    u_data = await self.reader.readline()
                    if not u_data:
                        continue
                    uname = u_data.decode('utf-8', 'ignore').strip()
                    u_row = self.server.db.get_user(uname)
                    if not u_row:
                        await self.send(ANSI_RED + "User not found.\n" + ANSI_RESET)
                        continue
                    self.server.db.grant_board_access(board_type, b_id, u_row['id'])
                    await self.send(ANSI_GREEN + "Access granted.\n" + ANSI_RESET)
                elif sub == '3':
                    await self.send(ANSI_CYAN + "Enter username to revoke access: " + ANSI_RESET)
                    u_data = await self.reader.readline()
                    if not u_data:
                        continue
                    uname = u_data.decode('utf-8', 'ignore').strip()
                    u_row = self.server.db.get_user(uname)
                    if not u_row:
                        await self.send(ANSI_RED + "User not found.\n" + ANSI_RESET)
                        continue
                    self.server.db.revoke_board_access(board_type, b_id, u_row['id'])
                    await self.send(ANSI_GREEN + "Access revoked.\n" + ANSI_RESET)
                elif sub == '4':
                    # Set minimum age
                    await self.send(ANSI_CYAN + "Enter new minimum age (0 for none): " + ANSI_RESET)
                    age_data = await self.reader.readline()
                    if not age_data:
                        continue
                    try:
                        new_age = int(age_data.decode('utf-8', 'ignore').strip())
                    except ValueError:
                        await self.send(ANSI_RED + "Invalid age.\n" + ANSI_RESET)
                        continue
                    if board_type == 'msg':
                        self.server.db.conn.execute('UPDATE boards SET min_age = ? WHERE id = ?', (new_age, b_id))
                    else:
                        # File areas
                        self.server.db.conn.execute('UPDATE file_areas SET min_age = ? WHERE id = ?', (new_age, b_id))
                    self.server.db.conn.commit()
                    board_row['min_age'] = new_age
                    await self.send(ANSI_GREEN + "Minimum age updated.\n" + ANSI_RESET)
                else:
                    await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def sysop_manage_levels(self) -> None:
        """SysOp function to view and modify user level definitions in the config file."""
        global CONFIG
        while True:
            # Show current levels
            levels = []
            if CONFIG and CONFIG.has_section('levels'):
                for lev, label in sorted(CONFIG['levels'].items(), key=lambda x: int(x[0])):
                    levels.append(f"{lev} -> {label}")
            await self.send(ANSI_BOLD + ANSI_MAGENTA + "\nUser Levels\n" + ANSI_RESET + "\n" + "\n".join(levels) + "\n")
            await self.send("1) Add/update level\n2) Delete level\n0) Back\n")
            choice = await self.prompt()
            if choice == '0':
                # Persist changes to disk
                with open(CONFIG_PATH, 'w') as f:
                    CONFIG.write(f)
                return
            elif choice == '1':
                await self.send(ANSI_CYAN + "Enter level number: " + ANSI_RESET)
                data = await self.reader.readline()
                if not data:
                    continue
                try:
                    level_num = data.decode('utf-8', 'ignore').strip()
                    int(level_num)  # Validate integer
                except ValueError:
                    await self.send(ANSI_RED + "Invalid level number.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter label for this level: " + ANSI_RESET)
                label_data = await self.reader.readline()
                if not label_data:
                    continue
                label = label_data.decode('utf-8', 'ignore').strip()
                if not CONFIG.has_section('levels'):
                    CONFIG.add_section('levels')
                CONFIG.set('levels', level_num, label)
                await self.send(ANSI_GREEN + "Level updated.\n" + ANSI_RESET)
            elif choice == '2':
                await self.send(ANSI_CYAN + "Enter level number to delete: " + ANSI_RESET)
                data = await self.reader.readline()
                if not data:
                    continue
                level_num = data.decode('utf-8', 'ignore').strip()
                if CONFIG.has_option('levels', level_num):
                    CONFIG.remove_option('levels', level_num)
                    await self.send(ANSI_GREEN + "Level removed.\n" + ANSI_RESET)
                else:
                    await self.send(ANSI_RED + "Level not found.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def sysop_manage_questions(self) -> None:
        """SysOp function to view and modify registration questions stored in the config file.

        Registration questions are defined under the 'questions' section of the INI
        configuration. Each entry maps an internal field name (used as the key
        when storing answers in the user_profiles table) to a prompt text shown
        to new users during account creation. This interface allows the SysOp
        to add, delete, rename or reorder these questions without editing the
        INI file manually. Changes are persisted back to disk upon exiting.

        The menu provides the following options:
          1) Add a new question (specify field name and prompt)
          2) Edit an existing question's prompt text
          3) Delete a question
          4) Reorder questions
          0) Save changes and return to the SysOp console
        """
        global CONFIG
        if CONFIG is None:
            await self.send(ANSI_RED + "Configuration not loaded.\n" + ANSI_RESET)
            return
        # Ensure questions section exists
        if not CONFIG.has_section('questions'):
            CONFIG.add_section('questions')
        # Work on a local list to preserve order while editing
        def get_questions_list() -> List[tuple[str, str]]:
            return list(CONFIG['questions'].items())
        def show_questions() -> str:
            items = get_questions_list()
            if not items:
                return "No registration questions defined."
            lines: List[str] = []
            editable_cfg = CONFIG['questions_editable'] if CONFIG.has_section('questions_editable') else {}
            for idx, (field, prompt) in enumerate(items, 1):
                editable = editable_cfg.get(field, 'true').lower() == 'true'
                edit_flag = 'E' if editable else 'N'
                lines.append(f"{idx}) {field} -> {prompt} [editable:{edit_flag}]")
            return "\n".join(lines)
        while True:
            # Display current questions
            await self.send(ANSI_BOLD + ANSI_MAGENTA + "\nRegistration Questions\n" + ANSI_RESET)
            await self.send(show_questions() + "\n")
            await self.send("1) Add question\n2) Edit question\n3) Delete question\n4) Reorder questions\n5) Toggle editability\n6) Set type/format\n0) Back\n")
            choice = await self.prompt()
            if choice == '0':
                # Write updated configuration back to disk
                with open(CONFIG_PATH, 'w') as f:
                    CONFIG.write(f)
                await self.send(ANSI_GREEN + "Registration questions saved.\n" + ANSI_RESET)
                return
            elif choice == '1':
                # Add new question
                await self.send(ANSI_CYAN + "Enter new field name (e.g. real_name): " + ANSI_RESET)
                fname_data = await self.reader.readline()
                if not fname_data:
                    continue
                field_name = fname_data.decode('utf-8', 'ignore').strip()
                # Validate field name (alphanumeric and underscores)
                if not re.match(r'^\w+$', field_name):
                    await self.send(ANSI_RED + "Invalid field name. Use letters, numbers or underscores only.\n" + ANSI_RESET)
                    continue
                if CONFIG.has_option('questions', field_name):
                    await self.send(ANSI_RED + "Field already exists. Use edit instead.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter prompt text for this question: " + ANSI_RESET)
                prompt_data = await self.reader.readline()
                if not prompt_data:
                    continue
                prompt_text = prompt_data.decode('utf-8', 'ignore').strip()
                CONFIG.set('questions', field_name, prompt_text)
                # Mark as editable by default
                if not CONFIG.has_section('questions_editable'):
                    CONFIG.add_section('questions_editable')
                CONFIG.set('questions_editable', field_name, 'true')
                await self.send(ANSI_GREEN + "Question added.\n" + ANSI_RESET)
            elif choice == '2':
                # Edit existing question's prompt
                items = get_questions_list()
                if not items:
                    await self.send(ANSI_RED + "No questions to edit.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter question number to edit: " + ANSI_RESET)
                num_data = await self.reader.readline()
                if not num_data:
                    continue
                try:
                    idx = int(num_data.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid number.\n" + ANSI_RESET)
                    continue
                if idx < 1 or idx > len(items):
                    await self.send(ANSI_RED + "Question number out of range.\n" + ANSI_RESET)
                    continue
                field, old_prompt = items[idx - 1]
                await self.send(ANSI_CYAN + f"Current prompt: {old_prompt}\nEnter new prompt: " + ANSI_RESET)
                pd = await self.reader.readline()
                if not pd:
                    continue
                new_prompt = pd.decode('utf-8', 'ignore').strip()
                CONFIG.set('questions', field, new_prompt)
                await self.send(ANSI_GREEN + "Prompt updated.\n" + ANSI_RESET)
            elif choice == '3':
                # Delete question
                items = get_questions_list()
                if not items:
                    await self.send(ANSI_RED + "No questions to delete.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter question number to delete: " + ANSI_RESET)
                ddata = await self.reader.readline()
                if not ddata:
                    continue
                try:
                    idx = int(ddata.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid number.\n" + ANSI_RESET)
                    continue
                if idx < 1 or idx > len(items):
                    await self.send(ANSI_RED + "Question number out of range.\n" + ANSI_RESET)
                    continue
                field, _ = items[idx - 1]
                CONFIG.remove_option('questions', field)
                await self.send(ANSI_GREEN + "Question removed.\n" + ANSI_RESET)
            elif choice == '4':
                # Reorder questions: ask user for comma‑separated list of indices in desired order
                items = get_questions_list()
                if len(items) < 2:
                    await self.send(ANSI_RED + "Not enough questions to reorder.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter the new order as comma‑separated question numbers (e.g. 2,1,3): " + ANSI_RESET)
                order_data = await self.reader.readline()
                if not order_data:
                    continue
                order_str = order_data.decode('utf-8', 'ignore').strip()
                try:
                    order = [int(x.strip()) for x in order_str.split(',') if x.strip()]
                except ValueError:
                    await self.send(ANSI_RED + "Invalid order format.\n" + ANSI_RESET)
                    continue
                if sorted(order) != list(range(1, len(items) + 1)):
                    await self.send(ANSI_RED + "Order must include each question number exactly once.\n" + ANSI_RESET)
                    continue
                # Build new ordered list
                new_items: List[tuple[str, str]] = [items[i - 1] for i in order]
                # Remove and readd in new order
                CONFIG.remove_section('questions')
                CONFIG.add_section('questions')
                for field, prompt in new_items:
                    CONFIG.set('questions', field, prompt)
                await self.send(ANSI_GREEN + "Questions reordered.\n" + ANSI_RESET)
            elif choice == '5':
                # Toggle whether a question is editable by users
                items = get_questions_list()
                if not items:
                    await self.send(ANSI_RED + "No questions to modify.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter question number to toggle editability: " + ANSI_RESET)
                idx_data = await self.reader.readline()
                if not idx_data:
                    continue
                try:
                    idx = int(idx_data.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid number.\n" + ANSI_RESET)
                    continue
                if idx < 1 or idx > len(items):
                    await self.send(ANSI_RED + "Question number out of range.\n" + ANSI_RESET)
                    continue
                field, _ = items[idx - 1]
                # Ensure section exists
                if not CONFIG.has_section('questions_editable'):
                    CONFIG.add_section('questions_editable')
                current = CONFIG['questions_editable'].get(field, 'true').lower() == 'true'
                new_val = 'false' if current else 'true'
                CONFIG.set('questions_editable', field, new_val)
                await self.send(ANSI_GREEN + f"Editability for {field} set to {new_val}.\n" + ANSI_RESET)
            elif choice == '6':
                # Set question type and format
                items = get_questions_list()
                if not items:
                    await self.send(ANSI_RED + "No questions defined.\n" + ANSI_RESET)
                    continue
                await self.send(ANSI_CYAN + "Enter question number to set type/format: " + ANSI_RESET)
                idx_data = await self.reader.readline()
                if not idx_data:
                    continue
                try:
                    idx = int(idx_data.decode('utf-8', 'ignore').strip())
                except ValueError:
                    await self.send(ANSI_RED + "Invalid number.\n" + ANSI_RESET)
                    continue
                if idx < 1 or idx > len(items):
                    await self.send(ANSI_RED + "Question number out of range.\n" + ANSI_RESET)
                    continue
                field, _ = items[idx - 1]
                # Ask type
                await self.send(ANSI_CYAN + "Enter type for this field (text/date/number/email): " + ANSI_RESET)
                tdata = await self.reader.readline()
                if not tdata:
                    continue
                typ = tdata.decode('utf-8', 'ignore').strip().lower()
                if typ not in ('text', 'date', 'number', 'email'):
                    await self.send(ANSI_RED + "Unsupported type.\n" + ANSI_RESET)
                    continue
                if not CONFIG.has_section('question_types'):
                    CONFIG.add_section('question_types')
                CONFIG.set('question_types', field, typ)
                # If date type, ask for format
                if typ == 'date':
                    await self.send(ANSI_CYAN + "Enter date format string (e.g. %Y-%m-%d): " + ANSI_RESET)
                    fdata = await self.reader.readline()
                    if not fdata:
                        continue
                    fmt = fdata.decode('utf-8', 'ignore').strip()
                    if not CONFIG.has_section('question_formats'):
                        CONFIG.add_section('question_formats')
                    CONFIG.set('question_formats', field, fmt)
                await self.send(ANSI_GREEN + "Type/format updated.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def sysop_create_board(self) -> None:
        await self.send(ANSI_CYAN + "Enter board name: " + ANSI_RESET)
        data = await self.reader.readline()
        if not data:
            return
        name = data.decode('utf-8', 'ignore').strip()
        await self.send(ANSI_CYAN + "Enter description: " + ANSI_RESET)
        desc_data = await self.reader.readline()
        if not desc_data:
            return
        desc = desc_data.decode('utf-8', 'ignore').strip()
        # Ask for minimum user level
        # Show available levels from configuration
        level_options = []
        if CONFIG and CONFIG.has_section('levels'):
            for lev, label in CONFIG['levels'].items():
                level_options.append(f"{lev} ({label})")
        else:
            level_options.append("0 (Guest)")
        await self.send(ANSI_CYAN + "Available levels: " + ", ".join(level_options) + "\n" + ANSI_RESET)
        await self.send(ANSI_CYAN + "Enter minimum user level for this board (number): " + ANSI_RESET)
        lvl_data = await self.reader.readline()
        min_level = 0
        if lvl_data:
            try:
                min_level = int(lvl_data.decode('utf-8', 'ignore').strip())
            except ValueError:
                min_level = 0
        # Ask for minimum age
        await self.send(ANSI_CYAN + "Enter minimum age for this board (0 for none): " + ANSI_RESET)
        age_data = await self.reader.readline()
        min_age = 0
        if age_data:
            try:
                min_age = int(age_data.decode('utf-8', 'ignore').strip())
            except ValueError:
                min_age = 0
        # Insert board with min_age
        cur = self.server.db.conn.cursor()
        cur.execute('INSERT INTO boards (name, description, min_level, min_age) VALUES (?, ?, ?, ?)', (name, desc, min_level, min_age))
        self.server.db.conn.commit()
        await self.send(ANSI_GREEN + "Board created.\n" + ANSI_RESET)

    async def sysop_review_pms(self) -> None:
        """Allow SysOp to list and read all private messages, and toggle read receipt visibility."""
        while True:
            msgs = self.server.db.list_all_private_messages()
            lines = [ANSI_BOLD + ANSI_MAGENTA + "\nAll Private Messages\n" + ANSI_RESET]
            if msgs:
                for m in msgs:
                    status = 'Read' if m['read'] else 'Unread'
                    visibility = 'Visible' if m['receipt_visible'] else 'Hidden'
                    created = m['created_at'][:19].replace('T', ' ')
                    lines.append(f"{m['id']}) {m['from_user']} -> {m['to_user']} - {m['subject']} ({status}, receipt {visibility}, {created})")
            else:
                lines.append("No messages.")
            lines.append("0) Back")
            await self.send("\n".join(lines) + "\n")
            choice = await self.prompt()
            if choice == '0':
                return
            try:
                msg_id = int(choice)
            except ValueError:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                continue
            msg = None
            for m in msgs:
                if m['id'] == msg_id:
                    msg = m
                    break
            if not msg:
                await self.send(ANSI_RED + "Message not found.\n" + ANSI_RESET)
                continue
            # Show message
            lines = [ANSI_CYAN + f"\nFrom: {msg['from_user']}\nTo: {msg['to_user']}\nSubject: {msg['subject']}\nDate: {msg['created_at'][:19].replace('T',' ')}\n" + ANSI_RESET]
            lines.append(msg['content'])
            # Options: toggle receipt visibility
            lines.append("\nOptions: v) Toggle receipt visibility, 0) Back")
            await self.send("\n".join(lines) + "\n")
            opt = await self.prompt()
            if opt == '0':
                continue
            elif opt.lower() == 'v':
                new_vis = not bool(msg['receipt_visible'])
                self.server.db.update_private_message_receipt_visible(msg['id'], new_vis)
                await self.send(ANSI_GREEN + f"Receipt visibility now {'enabled' if new_vis else 'disabled'}.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)

    async def sysop_check_update(self) -> None:
        """Allow the SysOp to check for updates and optionally download them.

        This method queries the configured update server for a newer version
        of the BBS. If a new version exists, the SysOp is shown the
        release notes and prompted to download and apply the update. The
        download will overwrite the current script after backing it up.
        A server restart is required to run the new version.
        """
        await self.send(ANSI_CYAN + "Checking for updates...\n" + ANSI_RESET)
        info = await self.server.check_for_update()
        if not info:
            await self.send(ANSI_GREEN + f"You are running the latest version ({__version__}).\n" + ANSI_RESET)
            return
        remote_ver = info.get('version', '')
        notes = info.get('notes', '')
        await self.send(ANSI_YELLOW + f"A new version {remote_ver} is available!\n" + ANSI_RESET)
        if notes:
            await self.send(ANSI_CYAN + "Release notes:\n" + notes + "\n" + ANSI_RESET)
        # Ask whether to download
        await self.send(ANSI_CYAN + "Would you like to download and apply the update now? (y/n): " + ANSI_RESET)
        ans = await self.safe_readline()
        if ans and ans.lower().startswith('y'):
            url = info.get('download_url', '')
            if not url:
                await self.send(ANSI_RED + "No download URL provided for update.\n" + ANSI_RESET)
                return
            ok = await self.server.download_update(url)
            if ok:
                await self.send(ANSI_GREEN + "Update downloaded successfully. Please restart the server to apply the new version.\n" + ANSI_RESET)
            else:
                await self.send(ANSI_RED + "Failed to download update. See server logs for details.\n" + ANSI_RESET)

    async def sysop_manage_handshakes(self) -> None:
        """
        Present pending handshake requests to the SysOp and allow approval or rejection.

        Each pending handshake is the result of an inbound handshake with a
        mismatched bootstrap secret. If the SysOp approves the request,
        the remote secret is stored in the database and our own
        handshake is initiated to exchange secrets. Rejected requests
        are removed from the pending list. The SysOp can exit the
        menu by selecting 0.
        """
        # If no pending handshakes exist, inform the SysOp
        if not self.server.pending_handshakes:
            await self.send(ANSI_MAGENTA + "\nNo pending handshake requests.\n" + ANSI_RESET)
            return
        while True:
            # Build a display of all pending requests
            lines: List[str] = []
            lines.append(ANSI_BOLD + ANSI_MAGENTA + "\nPending Handshake Requests\n" + ANSI_RESET)
            for idx, req in enumerate(self.server.pending_handshakes, start=1):
                from_host = req.get('from_host', 'unknown')
                lines.append(f"{idx}) {from_host}")
            lines.append("0) Back to SysOp menu")
            await self.send("\n".join(lines) + "\n")
            await self.send(ANSI_CYAN + "Select a handshake to approve/reject (0 to exit): " + ANSI_RESET)
            data = await self.reader.readline()
            if not data:
                return
            selection = data.decode('utf-8', 'ignore').strip()
            if not selection.isdigit():
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                continue
            idx = int(selection)
            if idx == 0:
                # Exit to sysop menu
                return
            if idx < 1 or idx > len(self.server.pending_handshakes):
                await self.send(ANSI_RED + "Invalid selection.\n" + ANSI_RESET)
                continue
            # Retrieve selected request
            req = self.server.pending_handshakes[idx - 1]
            from_host = req.get('from_host')
            payload = req.get('payload', {})
            remote_secret = payload.get('secret')
            # Ask for approval or rejection
            await self.send(ANSI_CYAN + f"Approve handshake from {from_host}? (y/n): " + ANSI_RESET)
            answer_data = await self.reader.readline()
            if not answer_data:
                return
            answer = answer_data.decode('utf-8', 'ignore').strip().lower()
            if answer != 'y':
                # Reject the handshake
                await self.send(ANSI_YELLOW + f"Handshake from {from_host} rejected.\n" + ANSI_RESET)
                # Remove from pending list
                try:
                    self.server.pending_handshakes.pop(idx - 1)
                except Exception:
                    pass
                continue
            # Approve: ensure remote secret is present
            if not from_host or not remote_secret:
                await self.send(ANSI_RED + "Malformed handshake payload; cannot approve.\n" + ANSI_RESET)
                # Remove invalid request and continue
                try:
                    self.server.pending_handshakes.pop(idx - 1)
                except Exception:
                    pass
                continue
            try:
                # Store the remote secret in the database
                self.server.db.set_link_secret(from_host, remote_secret)
                if hasattr(self.server, 'logger'):
                    self.server.logger.info(f"Manually approved handshake from {from_host}; stored remote secret")
                # Remove from pending list before initiating handshake
                self.server.pending_handshakes.pop(idx - 1)
            except Exception as e:
                await self.send(ANSI_RED + f"Failed to store secret for {from_host}: {e}\n" + ANSI_RESET)
                continue
            # Initiate our own handshake to send our secret to the remote host
            try:
                await self.server.initiate_handshake(from_host)
                await self.send(ANSI_GREEN + f"Handshake with {from_host} completed.\n" + ANSI_RESET)
            except Exception as e:
                await self.send(ANSI_RED + f"Error initiating handshake with {from_host}: {e}\n" + ANSI_RESET)
            # Loop to refresh list and allow handling of additional requests


class BBS:
    """Main server object that accepts connections and manages sessions."""

    def __init__(self, host: str, telnet_port: int, ssh_port: Optional[int] = None) -> None:
        self.host = host
        self.telnet_port = telnet_port
        self.ssh_port = ssh_port
        self.sessions: List[Session] = []
        self.db = Database(DB_PATH)
        global CONFIG
        if CONFIG is None:
            CONFIG = load_config(CONFIG_PATH)

        # Start remote queue worker after configuration loads
        self.remote_worker_task: Optional[asyncio.Task] = None
        # Worker parameters from configuration
        self.remote_retry_interval = 60  # seconds
        self.remote_max_attempts = 3
        self.remote_notify = True
        if CONFIG and CONFIG.has_section('remote'):
            try:
                self.remote_retry_interval = int(CONFIG.get('remote', 'retry_interval', fallback=str(self.remote_retry_interval)))
            except Exception:
                pass
            try:
                self.remote_max_attempts = int(CONFIG.get('remote', 'max_attempts', fallback=str(self.remote_max_attempts)))
            except Exception:
                pass
            self.remote_notify = CONFIG.get('remote', 'notify_on_failure', fallback='true').lower() == 'true'

        # Transfer throttling: bytes per second for file transfers. A value of
        # 0 means unlimited throughput. This setting controls how quickly the
        # remote worker sends file chunks to peers. When sending a chunk of
        # size N bytes (encoded as JSON), the worker will sleep for
        # N / transfer_rate seconds to approximate the desired bandwidth.
        self.transfer_rate = 0
        try:
            if CONFIG and CONFIG.has_section('remote'):
                self.transfer_rate = int(CONFIG.get('remote', 'transfer_rate', fallback='0'))
        except Exception:
            self.transfer_rate = 0
        # Chunk size for file transfers (in bytes). Files larger than this
        # threshold will be split into multiple remote tasks when synced to
        # peers. Base64 encoding increases size by ~33%%, so the actual JSON
        # payload will be larger than this value. Default is 65536 (64 KiB).
        self.transfer_chunk_size = 65536
        try:
            if CONFIG and CONFIG.has_section('remote'):
                self.transfer_chunk_size = int(CONFIG.get('remote', 'transfer_chunk_size', fallback='65536'))
        except Exception:
            self.transfer_chunk_size = 65536
        # Temporary storage for assembling inbound file chunks. Keyed by
        # (area_name, filename, from_host, uploaded_at). Each entry holds a
        # dictionary with 'chunks': a mapping from index to bytes, 'total'
        # number of chunks expected, and metadata fields such as uploader and
        # size. When all chunks are received, the file is assembled and
        # committed to disk.
        self.inbound_file_parts: Dict[tuple, Dict[str, any]] = {}

        # -----------------------------------------------------------------
        # Maintenance settings
        #
        # The maintenance subsystem periodically marks old posts and files
        # for expiration and later deletion. Settings are loaded from the
        # [maintenance] section of the configuration file. ``interval``
        # specifies how many hours between maintenance runs, and
        # ``grace_period`` specifies how many days an item remains in the
        # expired state before it is permanently removed. Defaults are
        # interval=24 hours and grace_period=7 days. These settings can
        # be adjusted via the configuration or future SysOp menus.
        self.maintenance_interval: float = 24 * 3600  # seconds
        self.maintenance_grace_days: int = 7
        if CONFIG and CONFIG.has_section('maintenance'):
            try:
                # Convert hours to seconds
                self.maintenance_interval = float(CONFIG.get('maintenance', 'interval', fallback='24')) * 3600
            except Exception:
                pass
            try:
                self.maintenance_grace_days = int(CONFIG.get('maintenance', 'grace_period', fallback=str(self.maintenance_grace_days)))
            except Exception:
                pass
        # Placeholder for the maintenance task. It will be created in
        # start() once the event loop is running.
        self.maintenance_task: Optional[asyncio.Task] = None

        # Security settings: login throttling and password complexity
        # Map IP to list of failed attempt timestamps (seconds since epoch)
        self.failed_logins: Dict[str, List[float]] = {}
        # Map IP to block expiry timestamp
        self.blocked_ips: Dict[str, float] = {}
        # Defaults for security parameters
        self.max_failed_attempts = 5
        self.fail_window = 60
        self.block_duration = 60
        self.password_complexity = 'none'
        if CONFIG and CONFIG.has_section('security'):
            try:
                self.max_failed_attempts = int(CONFIG.get('security', 'max_failed_attempts', fallback=str(self.max_failed_attempts)))
            except Exception:
                pass
            try:
                self.fail_window = int(CONFIG.get('security', 'fail_window', fallback=str(self.fail_window)))
            except Exception:
                pass
            try:
                self.block_duration = int(CONFIG.get('security', 'block_duration', fallback=str(self.block_duration)))
            except Exception:
                pass
            self.password_complexity = CONFIG.get('security', 'password_complexity', fallback=self.password_complexity)

        # Configure logging based on configuration settings. A SysOp can
        # specify the desired log level (debug, info, warning, error) and
        # optionally a log file in the [logging] section. If no file is
        # provided, logs go to stderr. This uses the standard logging module.
        log_level_str = 'info'
        log_file = ''
        if CONFIG and CONFIG.has_section('logging'):
            log_level_str = CONFIG.get('logging', 'level', fallback='info')
            log_file = CONFIG.get('logging', 'file', fallback='')
        level_map = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
        }
        log_level = level_map.get(log_level_str.lower(), logging.INFO)
        log_format = '%(asctime)s [%(levelname)s] %(message)s'
        if log_file:
            logging.basicConfig(level=log_level, format=log_format, filename=log_file)
        else:
            logging.basicConfig(level=log_level, format=log_format)
        self.logger = logging.getLogger('netbbsd')

        # Placeholder for update information. When check_for_update() finds a new
        # version, it will populate this attribute with a dict containing
        # 'version', 'notes' and possibly a 'download_url'. The SysOp can
        # review the information via the SysOp menu.
        self.update_available: Optional[dict] = None

        # Idle session timeout (in seconds). Sessions that do not send any
        # input within this period will be disconnected. This value is read
        # from the defaults section of the configuration file. A fallback of
        # 600 seconds (10 minutes) is used if not specified.
        self.idle_timeout = 600
        if CONFIG and CONFIG.has_section('defaults'):
            try:
                self.idle_timeout = int(CONFIG.get('defaults', 'idle_timeout', fallback=str(self.idle_timeout)))
            except Exception:
                pass

        # Flag indicating whether this node is a master in the link mesh. A
        # master node may send control messages that peer nodes apply
        # automatically. Loaded from the configuration. Defaults to False.
        self.is_master = False
        if CONFIG and CONFIG.has_section('general'):
            self.is_master = CONFIG.get('general', 'is_master', fallback='false').lower() == 'true'

        # Host alias used for inter‑BBS communication. This value is used
        # when generating handshake messages and storing our own secret in
        # the link_keys table. It must be unique within the mesh and
        # corresponds to the 'hostname' setting in the configuration file.
        self.host_alias: str = 'localhost'
        if CONFIG and CONFIG.has_section('general'):
            self.host_alias = CONFIG.get('general', 'hostname', fallback=self.host_alias)

        # Read the bootstrap secret used to authenticate initial handshake
        # messages. If empty, it should have been generated and saved
        # during configuration creation.
        self.bootstrap_secret: str = ''
        if CONFIG and CONFIG.has_section('security'):
            self.bootstrap_secret = CONFIG.get('security', 'bootstrap_secret', fallback='')

        # Ensure that we have a local secret stored in the database. This
        # secret will be used when establishing new links with peers. It is
        # stored in the link_keys table keyed by our host alias. If no
        # secret exists, a new one is generated and persisted. The secret
        # itself is not exposed via the configuration file for security.
        try:
            self.local_secret: str = self.db.ensure_local_secret(self.host_alias)
        except Exception as e:
            # Fall back to a static secret if DB operations fail. This
            # should not happen in normal operation but prevents crashes.
            self.local_secret = 'localsecretfallback'
            if hasattr(self, 'logger'):
                self.logger.error(f"Failed to initialize local secret: {e}")

        # Port used for incoming link (HTTP) connections. Peers send remote
        # synchronization messages to this port. Read from configuration
        # general.link_port. Default to 8686 if not specified.
        self.link_port = 8686
        if CONFIG and CONFIG.has_section('general'):
            try:
                self.link_port = int(CONFIG.get('general', 'link_port', fallback=str(self.link_port)))
            except Exception:
                pass

        # SSH configuration: determine whether SSH should be enabled and on
        # which port. Even if AsyncSSH is not installed, we read these
        # settings so that SysOps can set them in advance or be notified
        # when SSH support is unavailable.
        self.ssh_enabled = False
        self.ssh_port = 2222
        if CONFIG and CONFIG.has_section('general'):
            try:
                self.ssh_port = int(CONFIG.get('general', 'ssh_port', fallback=str(self.ssh_port)))
            except Exception:
                pass
            self.ssh_enabled = CONFIG.get('general', 'enable_ssh', fallback='false').lower() == 'true'

        # Pending handshake requests awaiting manual approval. Each entry
        # contains the raw payload and remote host alias for later
        # inspection by the SysOp. When a handshake is accepted, its
        # secret will be stored in the link_keys table. This list is
        # processed via a future SysOp menu.
        self.pending_handshakes: List[Dict[str, Any]] = []

    def _get_link_secret(self, host: str) -> Optional[str]:
        """
        Return the shared secret for a given linked host. Secrets are stored
        either in the link_keys table (preferred) or in the legacy
        [link_keys] section of the configuration file. Returns None if
        no secret is configured.

        The secret is used to sign outbound payloads using HMAC.
        """
        # First try to fetch from the database. This allows secrets to
        # be managed dynamically (e.g. via handshake) instead of being
        # hardcoded in the configuration file. If the database lookup
        # fails or returns None, fall back to the configuration section
        # for backward compatibility.
        try:
            secret = self.db.get_link_secret(host)
            if secret:
                return secret
        except Exception:
            pass
        # Legacy fallback: read from config if present
        if CONFIG and CONFIG.has_section('link_keys'):
            try:
                return CONFIG.get('link_keys', host)
            except Exception:
                pass
        return None

    def _sign_payload(self, secret: str, payload: dict) -> str:
        """
        Compute a signature for a payload using a shared secret. The
        signature is an HMAC of the canonical JSON representation of the
        payload using SHA256. The payload must not include a 'signature'
        field when passed into this method. Returns the hex digest of the
        signature.
        """
        try:
            import hmac
            import hashlib
            # Use sorted keys to ensure consistent ordering
            message = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
            return hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()
        except Exception:
            # Fallback: simple hash if hmac unavailable
            return hashlib.sha256((json.dumps(payload, sort_keys=True) + secret).encode('utf-8')).hexdigest()

    def prepare_remote_payload(self, host: str, payload: Dict[str, any]) -> Dict[str, any]:
        """
        Prepare a remote payload by adding version and signature fields. The
        returned payload is a shallow copy of the input with additional
        metadata. If a secret is configured for the target host under
        [link_keys], an HMAC signature is computed and attached. This
        method should be used before queuing a remote task.
        """
        out = dict(payload)  # shallow copy
        # Include our software version for compatibility checks on remote
        out['version'] = __version__
        # Indicate if this message is sent by a master node. Remote nodes
        # can use this flag to decide whether to accept control commands.
        out['master'] = self.is_master
        secret = self._get_link_secret(host)
        if secret:
            # Only sign the payload fields, excluding the signature itself
            try:
                signature = self._sign_payload(secret, out)
                out['signature'] = signature
            except Exception:
                # Logging of signature errors
                if hasattr(self, 'logger'):
                    self.logger.error(f"Failed to sign payload for host {host}")
        return out

    def verify_inbound_payload(self, payload: Dict[str, any]) -> (bool, str):
        """
        Verify an incoming remote payload. This checks that the payload
        contains the required metadata (from_host, signature, version) and
        validates the HMAC signature against the secret shared with the
        sending host. It also compares the remote version with our own.

        Returns a tuple (is_valid, message). If is_valid is False, the
        message describes the reason (e.g. 'invalid signature',
        'unknown host'). If the version differs but the message is still
        accepted, is_valid may be True with a warning message.
        """
        # Ensure from_host is provided
        from_host = payload.get('from_host')
        if not from_host:
            return False, 'missing from_host'
        # Extract and remove signature for verification
        sig = payload.get('signature')
        if not sig:
            return False, 'missing signature'
        # Copy payload without signature for verification
        tmp = dict(payload)
        tmp.pop('signature', None)
        # Look up secret for the sending host
        secret = self._get_link_secret(from_host)
        if not secret:
            return False, 'unknown host secret'
        # Compute expected signature
        expected = self._sign_payload(secret, tmp)
        if not hmac_compare(sig, expected):
            return False, 'invalid signature'
        # Check version compatibility. A simple check: major version match.
        remote_version = payload.get('version', '')
        if remote_version:
            try:
                local_major = __version__.split('.')[0]
                remote_major = str(remote_version).split('.')[0]
                if local_major != remote_major:
                    # Log mismatch but still accept; remote host will see version_mismatch
                    return False, 'version_mismatch'
            except Exception:
                pass
        return True, 'ok'

    def start_http_server(self) -> None:
        """
        Start a simple HTTP server on the configured link_port to accept
        inbound NetBBSD link messages. The server runs in a separate
        daemon thread so as not to block the asyncio event loop. It
        registers the BBS instance on the handler class so that the
        handler can call back into this BBS for message processing.
        """
        # Define request handler class within this method to capture self
        bbs = self
        class NetBBSDRequestHandler(http.server.BaseHTTPRequestHandler):
            # Silence default logging
            def log_message(self, format: str, *args) -> None:
                return
            def do_POST(self) -> None:
                # Only handle paths beginning with /netbbsd
                path = self.path
                content_length = int(self.headers.get('Content-Length', '0'))
                try:
                    body = self.rfile.read(content_length)
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    return
                # Attempt to parse JSON payload
                try:
                    payload = json.loads(body.decode('utf-8')) if body else {}
                except Exception:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'invalid_json'}).encode('utf-8'))
                    return
                # Handshake requests are handled specially using the bootstrap secret
                if path.startswith('/netbbsd/handshake'):
                    # Run handshake processing in the event loop and wait for result
                    loop = asyncio.get_event_loop()
                    future = asyncio.run_coroutine_threadsafe(bbs.handle_inbound_handshake(payload), loop)
                    try:
                        result = future.result(timeout=10.0)
                    except Exception as e:
                        # Failure while processing handshake
                        self.send_response(500)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': 'handshake_failed', 'detail': str(e)}).encode('utf-8'))
                        return
                    status = result.get('status')
                    if status == 'ok':
                        # Send the response payload to the caller
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(result.get('payload', {})).encode('utf-8'))
                    elif status == 'pending':
                        # Handshake requires manual approval
                        self.send_response(202)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'pending', 'message': 'handshake pending approval'}).encode('utf-8'))
                    else:
                        # Bad handshake request (signature mismatch etc.)
                        code = 403 if status == 'invalid_signature' else 400
                        self.send_response(code)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': status}).encode('utf-8'))
                    return

                # For other netbbsd messages, verify payload signature and version
                valid, reason = bbs.verify_inbound_payload(payload)
                if not valid:
                    # Distinguish protocol mismatch vs auth error
                    if reason == 'version_mismatch':
                        self.send_response(400)
                    else:
                        self.send_response(403)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': reason}).encode('utf-8'))
                    return
                # Accept the message and schedule processing on the event loop
                self.send_response(200)
                self.end_headers()
                # Hand off to the event loop for non‑blocking processing
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(asyncio.create_task, bbs.handle_inbound_message(path, payload))

        # Start the HTTP server in a background thread
        def run_server() -> None:
            with socketserver.ThreadingTCPServer((self.host, self.link_port), NetBBSDRequestHandler) as httpd:
                # Attach bbs reference to server and handler
                httpd.bbs = self
                httpd.serve_forever()
        import threading
        t = threading.Thread(target=run_server, daemon=True)
        t.start()

    async def start_ssh_server(self) -> None:
        """
        Start an SSH server using AsyncSSH if SSH support is enabled. This
        method should be called from within the asyncio event loop. If
        AsyncSSH is not installed, a warning is logged. Currently the
        SSH server acts as a stub and informs clients that SSH support
        is not yet fully implemented.
        """
        if not self.ssh_enabled:
            return
        # If AsyncSSH isn't available, warn the operator and return
        if not HAVE_ASYNCSSH:
            if hasattr(self, 'logger'):
                self.logger.warning('SSH is enabled in configuration but AsyncSSH is not installed.')
            else:
                print('SSH is enabled in configuration but AsyncSSH is not installed.', file=sys.stderr)
            return
        try:
            import asyncssh  # type: ignore

            async def process_factory(process: 'asyncssh.SSHServerProcess') -> None:
                """
                Simple process factory which informs connecting users that
                SSH support is not implemented. In a full implementation
                this would wrap a Session using process.stdin/stdout as
                reader/writer for the BBS. For now we just greet and exit.
                """
                process.stdout.write('SSH support is not yet implemented. Please use Telnet.\n')
                await process.stdout.drain()
                process.exit(0)

            await asyncssh.create_server(process_factory=process_factory,
                                         host=self.host,
                                         port=self.ssh_port)
            if hasattr(self, 'logger'):
                self.logger.info(f'SSH server listening on {self.host}:{self.ssh_port}')
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f'Failed to start SSH server: {e}')
            else:
                print(f'Failed to start SSH server: {e}', file=sys.stderr)

    async def broadcast_remote_chat(self, channel: str, message: str) -> None:
        """
        Broadcast a chat message received from a remote host to all
        connected sessions currently in the specified channel. Unlike
        the Session.broadcast_chat() method, this routine does not
        exclude a sender because the message originates externally.
        """
        # Iterate over all active sessions on the server
        for sess in list(self.sessions):
            try:
                if sess.in_chat and sess.current_channel == channel:
                    await sess.send(message)
            except Exception:
                # Ignore any errors sending to closed sessions
                continue

    async def handle_inbound_message(self, path: str, payload: Dict[str, any]) -> None:
        """
        Handle an inbound NetBBSD link message. This coroutine runs on the
        asyncio event loop. Depending on the path it will route the
        message to the appropriate handler. At this stage only remote
        private messages are processed. Board and chat syncing requires
        additional logic to merge threads or broadcast chat messages and
        is left as future work.
        """
        # Determine operation based on path
        if path == '/netbbsd/pm':
            # Remote private message
            to_user = payload.get('to_user')
            subject = payload.get('subject', '')
            content = payload.get('content', '')
            from_user = payload.get('from_user', '')
            from_host = payload.get('from_host', '')
            # Lookup local recipient
            user_row = self.db.get_user(to_user)
            if not user_row:
                # Unknown user – ignore the message but log
                if hasattr(self, 'logger'):
                    self.logger.warning(f"Inbound PM for unknown user '{to_user}' from {from_user}@{from_host}")
                return
            # Insert into local private messages with receipt_visible True
            self.db.add_private_message(0, user_row['id'], f"{from_user}@{from_host}: {subject}", content)
            # Optionally notify user if online; left as future work
            if hasattr(self, 'logger'):
                self.logger.info(f"Received remote PM from {from_user}@{from_host} to {to_user}")
            return
        elif path == '/netbbsd/board':
            # Remote board synchronization. The payload contains the board
            # name and a post dict describing either a new thread or a new
            # post. We map remote thread identifiers to local ones and
            # insert new threads/posts accordingly.
            board_name = payload.get('board')
            from_host = payload.get('from_host')
            post = payload.get('post', {})
            if not board_name or not post or not from_host:
                if hasattr(self, 'logger'):
                    self.logger.warning('Malformed remote board payload')
                return
            # Ensure the board exists locally
            board_row = self.db.get_board_by_name(board_name)
            if not board_row:
                # Create a new board for this remote board
                board_id = self.db.add_board(board_name, f'Linked board from {from_host}')
            else:
                board_id = board_row['id']
            ptype = post.get('type')
            # Remote author handling: try to map to a local user, otherwise use remote user
            author_username = post.get('author') or 'remote'
            author_row = self.db.get_user(author_username)
            if author_row:
                author_id = author_row['id']
            else:
                # Fallback to generic remote user
                author_id = self.db.ensure_remote_user()
            # Process based on post type
            if ptype == 'thread':
                remote_thread_id = post.get('id')
                title = post.get('title') or f'Remote thread {remote_thread_id}'
                # Create a new thread locally
                local_thread_id = self.db.add_thread(board_id, title, author_id)
                # Map remote thread id to local thread id for subsequent posts
                if remote_thread_id is not None:
                    self.db.insert_remote_thread_map(from_host, str(remote_thread_id), local_thread_id)
                # Optionally log the creation
                if hasattr(self, 'logger'):
                    self.logger.info(f'Imported remote thread "{title}" from {from_host} into board {board_name}')
            elif ptype == 'post':
                remote_thread_id = post.get('thread_id')
                if remote_thread_id is None:
                    # Cannot map post without thread id
                    if hasattr(self, 'logger'):
                        self.logger.warning('Remote post missing thread_id; dropping')
                    return
                # Lookup local thread id for this remote thread
                local_thread_id = self.db.get_local_thread_id(from_host, str(remote_thread_id))
                if not local_thread_id:
                    # Create a new thread if mapping not found
                    title = f'Remote thread {remote_thread_id}'
                    local_thread_id = self.db.add_thread(board_id, title, author_id)
                    self.db.insert_remote_thread_map(from_host, str(remote_thread_id), local_thread_id)
                content = post.get('content', '')
                approved = bool(post.get('approved', 1))
                # Sanitize content
                content = sanitize_text(content)
                # Retrieve pinned/exempt flags from payload
                pinned_flag = 1 if post.get('pinned', 0) else 0
                exempt_flag = 1 if post.get('exempt', 0) else 0
                # Add the post and get its ID
                post_id = self.db.add_post(local_thread_id, author_id, content, approved)
                # Update pinned/exempt flags if present
                if pinned_flag or exempt_flag:
                    try:
                        cur = self.db.conn.cursor()
                        cur.execute('UPDATE posts SET pinned = ?, exempt = ? WHERE id = ?', (pinned_flag, exempt_flag, post_id))
                        self.db.conn.commit()
                    except Exception:
                        pass
                if hasattr(self, 'logger'):
                    self.logger.info(f'Imported remote post into thread {local_thread_id} on board {board_name}')
            else:
                # Unknown post type
                if hasattr(self, 'logger'):
                    self.logger.warning(f'Unknown remote post type: {ptype}')
            return
        elif path == '/netbbsd/chat':
            # Remote chat message handling. The payload contains the
            # channel name and a message dict with nickname, content and
            # created_at. We ensure the channel exists and append the
            # message to chat history. Broadcasting to online users is
            # currently not implemented.
            channel_name = payload.get('channel')
            from_host = payload.get('from_host')
            message = payload.get('message', {})
            if not channel_name or not message or not from_host:
                if hasattr(self, 'logger'):
                    self.logger.warning('Malformed remote chat payload')
                return
            # Ensure channel exists; mark as linked (link=1)
            channel_row = self.db.get_channel(channel_name)
            if not channel_row:
                self.db.add_channel(channel_name, description=f'Linked channel from {from_host}', link=True)
            nickname = message.get('nickname', 'remote')
            content = message.get('content', '')
            # Create remote user for chat messages
            remote_uid = self.db.ensure_remote_user()
            # Prefix nickname with host to avoid confusion
            nick = f"{nickname}@{from_host}"
            self.db.add_chat_message(channel_name, remote_uid, nick, sanitize_text(content))
            # Format message similar to local chat: [HH:MM:SS] nick: content
            try:
                dt = datetime.fromisoformat(message.get('created_at')) if message.get('created_at') else datetime.utcnow()
            except Exception:
                dt = datetime.utcnow()
            ts = dt.strftime('%H:%M:%S')
            formatted = f"[{ts}] {nick}: {content}\n"
            # Broadcast to live sessions on this channel
            await self.broadcast_remote_chat(channel_name, formatted)
            if hasattr(self, 'logger'):
                self.logger.info(f'Imported remote chat message into {channel_name} from {from_host}')
            return
        elif path == '/netbbsd/file':
            # Remote file area synchronization. Payload contains the area
            # name and a file dict with filename, size, content (base64),
            # uploader and uploaded_at timestamp. We store the file in
            # our uploads directory and register it in the database. The
            # file content may be empty if remote host did not provide it.
            area_name = payload.get('area')
            from_host = payload.get('from_host')
            file_info = payload.get('file', {})
            if not area_name or not file_info or not from_host:
                if hasattr(self, 'logger'):
                    self.logger.warning('Malformed remote file payload')
                return
            filename = file_info.get('filename')
            uploader = file_info.get('uploader', 'remote')
            uploaded_at = file_info.get('uploaded_at') or datetime.utcnow().isoformat()
            # Remote file may be sent as single payload with 'content' or as multiple chunks with
            # 'data', 'chunk_index' and 'total_chunks'. Determine transfer key.
            chunk_index = file_info.get('chunk_index')
            total_chunks = file_info.get('total_chunks')
            # Ensure local file area exists
            cur = self.db.conn.cursor()
            cur.execute('SELECT * FROM file_areas WHERE name = ?', (area_name,))
            area_row = cur.fetchone()
            if not area_row:
                cur.execute('INSERT INTO file_areas (name, description, min_level, min_age, moderated, max_size) VALUES (?, ?, 0, 0, 0, 0)',
                            (area_name, f'Linked area from {from_host}'))
                self.db.conn.commit()
                area_id = cur.lastrowid
            else:
                area_id = area_row['id']
            dir_path = Path('uploads') / str(area_id)
            dir_path.mkdir(parents=True, exist_ok=True)
            # Single part transfer: content provided directly
            if chunk_index is None:
                # Validate presence of filename and content
                content_b64 = file_info.get('content', '')
                if not filename or content_b64 == '':
                    if hasattr(self, 'logger'):
                        self.logger.warning('Remote file payload missing filename or content')
                    return
                try:
                    import base64
                    data_bytes = base64.b64decode(content_b64.encode('ascii'))
                except Exception:
                    data_bytes = b''
                actual_size = len(data_bytes)
                # Enforce max size
                max_sz = 0
                try:
                    if CONFIG and CONFIG.has_section('file_areas') and CONFIG.has_option('file_areas', 'max_file_size'):
                        max_sz = int(CONFIG.get('file_areas', 'max_file_size', fallback='0'))
                    elif CONFIG:
                        max_sz = int(CONFIG.get('general', 'max_file_size', fallback='0'))
                except Exception:
                    max_sz = 0
                if max_sz and actual_size > max_sz:
                    if hasattr(self, 'logger'):
                        self.logger.warning(f"Remote file {filename} exceeds max size; skipped")
                    return
                # Validate filename: must not contain path separators or be absolute
                if os.path.sep in filename or (os.path.altsep and os.path.altsep in filename) or Path(filename).is_absolute():
                    if hasattr(self, 'logger'):
                        self.logger.warning(f"Rejected remote file with invalid filename: {filename}")
                    return
                file_path = (dir_path / filename).resolve()
                # Ensure file_path is within dir_path
                if not str(file_path).startswith(str(dir_path.resolve())):
                    if hasattr(self, 'logger'):
                        self.logger.warning(f"Rejected remote file with path traversal attempt: {filename}")
                    return
                try:
                    with open(file_path, 'wb') as fh:
                        fh.write(data_bytes)
                except Exception as e:
                    if hasattr(self, 'logger'):
                        self.logger.error(f'Error writing remote file {filename}: {e}')
                    return
                # Register uploader
                author_row = self.db.get_user(uploader)
                if author_row:
                    uploader_id = author_row['id']
                else:
                    uploader_id = self.db.ensure_remote_user()
                # Insert record
                cur.execute(
                    'INSERT INTO files (board_id, filename, uploader_id, uploaded_at, size, path) VALUES (?, ?, ?, ?, ?, ?)',
                    (area_id, filename, uploader_id, uploaded_at, actual_size, str(file_path))
                )
                file_id = cur.lastrowid
                # Apply pinned/exempt flags if provided in payload
                pinned_flag = 1 if file_info.get('pinned', 0) else 0
                exempt_flag = 1 if file_info.get('exempt', 0) else 0
                if pinned_flag or exempt_flag:
                    try:
                        cur.execute('UPDATE files SET pinned = ?, exempt = ? WHERE id = ?', (pinned_flag, exempt_flag, file_id))
                    except Exception:
                        pass
                self.db.conn.commit()
                if hasattr(self, 'logger'):
                    self.logger.info(f'Imported remote file {filename} into area {area_name} from {from_host}')
                return
            else:
                # Multi‑part transfer: accumulate chunks
                try:
                    part_index = int(chunk_index)
                    total = int(total_chunks)
                except Exception:
                    if hasattr(self, 'logger'):
                        self.logger.warning('Invalid chunk metadata in remote file payload')
                    return
                data_b64 = file_info.get('data', '')
                if not filename or data_b64 == '':
                    if hasattr(self, 'logger'):
                        self.logger.warning('Remote file chunk missing filename or data')
                    return
                import base64
                try:
                    part_bytes = base64.b64decode(data_b64.encode('ascii'))
                except Exception:
                    part_bytes = b''
                # Assemble key and ensure entry exists
                key = (area_name, filename, from_host, uploaded_at)
                entry = self.inbound_file_parts.get(key)
                if not entry:
                    entry = {
                        'chunks': {},
                        'total': total,
                        'uploader': uploader,
                        'size': file_info.get('size'),
                        'uploaded_at': uploaded_at,
                    }
                    self.inbound_file_parts[key] = entry
                entry['chunks'][part_index] = part_bytes
                # If all chunks arrived, assemble
                if len(entry['chunks']) >= entry['total']:
                    # Combine chunks in order
                    assembled = bytearray()
                    for i in range(entry['total']):
                        assembled.extend(entry['chunks'].get(i, b''))
                    actual_size = len(assembled)
                    # Enforce max size
                    max_sz = 0
                    try:
                        if CONFIG and CONFIG.has_section('file_areas') and CONFIG.has_option('file_areas', 'max_file_size'):
                            max_sz = int(CONFIG.get('file_areas', 'max_file_size', fallback='0'))
                        elif CONFIG:
                            max_sz = int(CONFIG.get('general', 'max_file_size', fallback='0'))
                    except Exception:
                        max_sz = 0
                    if max_sz and actual_size > max_sz:
                        if hasattr(self, 'logger'):
                            self.logger.warning(f"Remote file {filename} exceeds max size after assembly; skipped")
                        # Clean up
                        del self.inbound_file_parts[key]
                        return
                    file_path = dir_path / filename
                    try:
                        with open(file_path, 'wb') as fh:
                            fh.write(assembled)
                    except Exception as e:
                        if hasattr(self, 'logger'):
                            self.logger.error(f'Error writing assembled remote file {filename}: {e}')
                        del self.inbound_file_parts[key]
                        return
                    # Register uploader
                    author_row = self.db.get_user(uploader)
                    if author_row:
                        uploader_id = author_row['id']
                    else:
                        uploader_id = self.db.ensure_remote_user()
                    # Insert into files table
                    cur.execute(
                        'INSERT INTO files (board_id, filename, uploader_id, uploaded_at, size, path) VALUES (?, ?, ?, ?, ?, ?)',
                        (area_id, filename, uploader_id, uploaded_at, actual_size, str(file_path))
                    )
                    self.db.conn.commit()
                    if hasattr(self, 'logger'):
                        self.logger.info(f'Imported remote file {filename} (multi‑part) into area {area_name} from {from_host}')
                    # Clean up completed entry
                    del self.server.inbound_file_parts[key]
                return
        else:
            # Unknown endpoint
            if hasattr(self, 'logger'):
                self.logger.warning(f"Unknown inbound path: {path}")
            return

    async def handle_inbound_handshake(self, payload: Dict[str, any]) -> Dict[str, any]:
        """
        Process an inbound handshake request. Runs on the event loop.
        A handshake payload must include 'from_host', 'secret' and 'signature'.
        The signature is verified using this node's bootstrap secret. If
        valid, the remote secret is stored and a response containing our
        host alias and secret is returned. If invalid, the request is
        queued for manual approval and a pending status is returned.

        Returns a dict with keys:
          - status: 'ok', 'pending', 'invalid_signature', 'bad_request' or 'error'
          - payload: present when status == 'ok', containing our reply
        """
        from_host = payload.get('from_host')
        remote_secret = payload.get('secret')
        sig = payload.get('signature')
        if not (from_host and remote_secret and sig):
            return {'status': 'bad_request'}
        # Copy payload without signature
        base = dict(payload)
        base.pop('signature', None)
        # Compute expected signature using bootstrap secret
        try:
            expected = self._sign_payload(self.bootstrap_secret, base)
        except Exception:
            return {'status': 'invalid_signature'}
        # Compare signatures
        if not hmac_compare(sig, expected):
            # Queue for manual approval
            try:
                self.pending_handshakes.append({'from_host': from_host, 'payload': payload})
            except Exception:
                pass
            if hasattr(self, 'logger'):
                self.logger.info(f"Handshake from {from_host} pending manual approval")
            return {'status': 'pending'}
        # Accept: store remote secret
        try:
            self.db.set_link_secret(from_host, remote_secret)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Failed to save remote secret for {from_host}: {e}")
            return {'status': 'error'}
        # Ensure our local secret exists
        try:
            self.local_secret = self.db.ensure_local_secret(self.host_alias)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Failed to ensure local secret: {e}")
        # Build response payload
        resp_base = {
            'from_host': self.host_alias,
            'secret': self.local_secret,
            'version': __version__,
        }
        # Sign response with bootstrap secret
        try:
            resp_sig = self._sign_payload(self.bootstrap_secret, resp_base)
            resp_base['signature'] = resp_sig
        except Exception:
            pass
        if hasattr(self, 'logger'):
            self.logger.info(f"Handshake with {from_host} succeeded; secret stored")
        return {'status': 'ok', 'payload': resp_base}

    async def handle_telnet_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = Session(reader, writer, self)
        self.sessions.append(session)
        try:
            if not await session.handle_login():
                await session.close()
                return
            await session.main_menu()
        finally:
            self.sessions.remove(session)
            await session.close()

    async def start(self) -> None:
        # Start inbound HTTP server for link messages. This call returns
        # immediately after spawning a background thread. It is important
        # to start the HTTP server before accepting telnet clients to
        # avoid losing remote messages on startup.
        self.start_http_server()
        # Start SSH server if enabled. This will no‑op if disabled or
        # AsyncSSH is not installed. We do not await this call because
        # asyncssh.create_server returns immediately when using the
        # process_factory; it registers the server with the loop.
        await self.start_ssh_server()
        # Launch telnet server for interactive sessions
        server = await asyncio.start_server(self.handle_telnet_client, host=self.host, port=self.telnet_port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets) if server.sockets else 'unknown'
        print(f'Telnet server listening on {addrs}')
        # Start remote worker when server starts
        if self.remote_worker_task is None:
            self.remote_worker_task = asyncio.create_task(self.remote_worker())
        # Start maintenance worker to periodically expire and delete old posts
        # and files. The worker runs in the background according to
        # self.maintenance_interval. Only create the task once.
        if self.maintenance_task is None:
            self.maintenance_task = asyncio.create_task(self.maintenance_worker())

        # Initiate handshakes with configured link hosts. This will run
        # asynchronously and store secrets for any hosts that do not
        # already have a shared secret. Handshakes with mismatched
        # bootstrap secrets will be queued for manual approval. We do
        # not await this task here because handshake_initiate_worker may
        # perform network I/O and should run in the background.
        asyncio.create_task(self.handshake_initiate_worker())
        async with server:
            await server.serve_forever()

    # ---------------------------------------------------------------------
    # Remote linking and messaging
    #
    async def send_remote_pm(self, from_user: User, to_name: str, host: str, subject: str, content: str) -> bool:
        """Queue a remote private message to be sent via the remote queue worker.

        Returns True if the task was enqueued, False if the host is unknown.
        """
        # Ensure host is configured
        if not CONFIG or not CONFIG.has_section('link_hosts') or not CONFIG.has_option('link_hosts', host):
            print(f"Remote host '{host}' not configured", file=sys.stderr)
            return False
        # Build payload
        base_payload = {
            'from_user': from_user.username,
            'from_host': CONFIG.get('general', 'hostname', fallback='local') if CONFIG else 'local',
            'to_user': to_name,
            'subject': subject,
            'content': content,
        }
        # Prepare signed payload
        payload = self.prepare_remote_payload(host, base_payload)
        endpoint = '/netbbsd/pm'
        self.db.enqueue_remote_task('pm', host, endpoint, payload, self.remote_max_attempts)
        return True

    async def sync_link_board(self, board_name: str, post_payload: Dict[str, str]) -> None:
        """Queue a board post for synchronization to linked hosts.

        The [link_boards] section of the configuration maps board names to a
        comma‑separated list of hostnames. For each host, this method
        enqueues a remote task instead of performing an immediate HTTP
        call. The background remote worker will attempt delivery and
        retry on failure according to configured policies.
        """
        if not CONFIG or not CONFIG.has_section('link_boards'):
            return
        peers = CONFIG.get('link_boards', board_name, fallback='')
        if not peers:
            return
        hosts = [h.strip() for h in peers.split(',') if h.strip()]
        if not hosts:
            return
        # Compose payload with our host name and post info
        base_payload = {
            'board': board_name,
            'from_host': CONFIG.get('general', 'hostname', fallback='local') if CONFIG else 'local',
            'post': post_payload,
        }
        for host in hosts:
            # Validate host configured
            if not CONFIG or not CONFIG.has_section('link_hosts') or not CONFIG.has_option('link_hosts', host):
                # Log unknown host
                if hasattr(self, 'logger'):
                    self.logger.error(f"Linked host '{host}' not configured")
                else:
                    print(f"Linked host '{host}' not configured", file=sys.stderr)
                continue
            # Enqueue remote task for board sync
            endpoint = '/netbbsd/board'
            # Prepare payload with version and signature
            payload = self.prepare_remote_payload(host, base_payload)
            self.db.enqueue_remote_task('board', host, endpoint, payload, self.remote_max_attempts)

    async def sync_link_channel(self, channel_name: str, message_payload: Dict[str, str]) -> None:
        """Queue a chat message for synchronization to linked hosts.

        The [link_channels] section of the configuration maps channel names to
        comma‑separated hostnames. For each host, enqueue a remote task to
        deliver the chat message. The remote worker handles retries.
        """
        if not CONFIG or not CONFIG.has_section('link_channels'):
            return
        peers = CONFIG.get('link_channels', channel_name, fallback='')
        if not peers:
            return
        hosts = [h.strip() for h in peers.split(',') if h.strip()]
        if not hosts:
            return
        base_payload = {
            'channel': channel_name,
            'from_host': CONFIG.get('general', 'hostname', fallback='local') if CONFIG else 'local',
            'message': message_payload,
        }
        for host in hosts:
            if not CONFIG or not CONFIG.has_section('link_hosts') or not CONFIG.has_option('link_hosts', host):
                if hasattr(self, 'logger'):
                    self.logger.error(f"Linked host '{host}' not configured")
                else:
                    print(f"Linked host '{host}' not configured", file=sys.stderr)
                continue
            endpoint = '/netbbsd/chat'
            payload = self.prepare_remote_payload(host, base_payload)
            self.db.enqueue_remote_task('chat', host, endpoint, payload, self.remote_max_attempts)

    async def sync_link_area(self, area_name: str, file_payload: Dict[str, str]) -> None:
        """Queue a file upload for synchronization to linked hosts.

        The [link_areas] section of the configuration maps file area names
        (formerly called file boards) to comma‑separated hostnames. For each
        host in the list, this method enqueues a remote task. The
        background remote worker will attempt delivery and handle
        retries according to the configured policies. The payload should
        include the filename, uploader, size, and content encoded in
        base64 along with a timestamp.
        """
        if not CONFIG or not CONFIG.has_section('link_areas'):
            return
        peers = CONFIG.get('link_areas', area_name, fallback='')
        if not peers:
            return
        hosts = [h.strip() for h in peers.split(',') if h.strip()]
        if not hosts:
            return
        # Determine our hostname for inclusion in payload
        from_host = CONFIG.get('general', 'hostname', fallback='local') if CONFIG else 'local'
        # Raw bytes for chunking. file_payload may contain 'content' (base64) or chunk data
        import base64
        raw_bytes: bytes = b''
        if 'content' in file_payload and file_payload['content']:
            try:
                raw_bytes = base64.b64decode(file_payload['content'].encode('ascii'))
            except Exception:
                raw_bytes = b''
        else:
            # If there is no content field (e.g. we are chunking from zmodem), skip
            pass
        total_size = len(raw_bytes)
        # Determine chunk size; if zero or raw_bytes empty, treat as single chunk
        cs = self.transfer_chunk_size if self.transfer_chunk_size > 0 else len(raw_bytes)
        total_chunks = (len(raw_bytes) + cs - 1) // cs if cs else 1
        for host in hosts:
            # Validate host configured
            if not CONFIG or not CONFIG.has_section('link_hosts') or not CONFIG.has_option('link_hosts', host):
                if hasattr(self, 'logger'):
                    self.logger.error(f"Linked host '{host}' not configured")
                else:
                    print(f"Linked host '{host}' not configured", file=sys.stderr)
                continue
            endpoint = '/netbbsd/file'
            if total_chunks <= 1 or len(raw_bytes) == 0:
                # Single part transfer. Include original file_payload
                base_payload = {
                    'area': area_name,
                    'from_host': from_host,
                    'file': file_payload,
                }
                payload = self.prepare_remote_payload(host, base_payload)
                self.db.enqueue_remote_task('file', host, endpoint, payload, self.remote_max_attempts)
            else:
                # Multi‑part transfer
                for idx in range(total_chunks):
                    chunk = raw_bytes[idx * cs:(idx + 1) * cs]
                    b64chunk = base64.b64encode(chunk).decode('ascii')
                    chunk_payload = {
                        'area': area_name,
                        'from_host': from_host,
                        'file': {
                            'filename': file_payload.get('filename'),
                            'size': file_payload.get('size'),
                            'uploader': file_payload.get('uploader'),
                            'uploaded_at': file_payload.get('uploaded_at'),
                            'chunk_index': idx,
                            'total_chunks': total_chunks,
                            'data': b64chunk,
                        }
                    }
                    payload = self.prepare_remote_payload(host, chunk_payload)
                    self.db.enqueue_remote_task('file', host, endpoint, payload, self.remote_max_attempts)

    # ---------------------------------------------------------------------
    # Update checking and downloading
    #
    def _parse_version(self, ver: str) -> List[int]:
        """Convert a semantic version string into a list of integers for comparison.

        Non-integer components are ignored. For example, '1.2.3' becomes
        [1, 2, 3]. Missing components are considered zero when comparing
        different length versions.
        """
        parts: List[int] = []
        for part in ver.split('.'):
            try:
                parts.append(int(part))
            except ValueError:
                # Ignore non-numeric parts (e.g. alpha/beta tags)
                break
        return parts

    def _compare_versions(self, a: str, b: str) -> int:
        """Compare two version strings a and b.

        Returns 1 if a > b, -1 if a < b, 0 if equal. This uses a simple
        numeric comparison of dot-separated version components. Pre-release
        tags are not considered.
        """
        va = self._parse_version(a)
        vb = self._parse_version(b)
        max_len = max(len(va), len(vb))
        va += [0] * (max_len - len(va))
        vb += [0] * (max_len - len(vb))
        for x, y in zip(va, vb):
            if x > y:
                return 1
            if x < y:
                return -1
        return 0

    async def check_for_update(self) -> Optional[dict]:
        """Check the configured update URL for a newer version.

        This coroutine fetches the version information from the URL specified
        in the [update] section of the configuration. If a newer version
        than the current __version__ is available, a dictionary with the
        remote version, notes and download URL is returned. Otherwise,
        None is returned. Network errors are silently ignored.
        """
        if CONFIG is None or not CONFIG.has_section('update'):
            return None
        check_url = CONFIG.get('update', 'check_url', fallback='')
        if not check_url:
            return None
        try:
            with urllib.request.urlopen(check_url, timeout=10) as resp:
                data = resp.read()
                info = json.loads(data.decode('utf-8'))
        except Exception:
            return None
        remote_ver = info.get('version', '')
        notes = info.get('notes', '')
        download_url = info.get('download_url') or CONFIG.get('update', 'download_url', fallback='')
        if remote_ver and self._compare_versions(remote_ver, __version__) > 0:
            return {'version': remote_ver, 'notes': notes, 'download_url': download_url}
        return None

    async def initiate_handshake(self, host: str) -> None:
        """
        Initiate a handshake with a remote host. If a secret is already
        stored for the given host, this method returns immediately. The
        handshake payload includes our host alias and local secret and is
        signed with the bootstrap secret. The response is expected to
        include the remote host alias and its secret, also signed with
        the bootstrap secret. On success, the remote secret is stored
        in the database. Errors are logged.

        :param host: Host alias from the [link_hosts] section
        """
        # Skip if secret already exists
        try:
            if self.db.get_link_secret(host):
                return
        except Exception:
            pass
        # Determine remote URL
        if not CONFIG or not CONFIG.has_section('link_hosts') or not CONFIG.has_option('link_hosts', host):
            if hasattr(self, 'logger'):
                self.logger.warning(f"Cannot initiate handshake: host '{host}' not configured")
            return
        base_url = CONFIG.get('link_hosts', host)
        # Build handshake URL (assumes HTTP/HTTPS URL without trailing slash)
        handshake_url = base_url.rstrip('/') + '/netbbsd/handshake'
        # Build payload
        payload = {
            'from_host': self.host_alias,
            'secret': self.local_secret,
            'version': __version__,
        }
        # Sign payload with bootstrap secret
        try:
            sig = self._sign_payload(self.bootstrap_secret, payload)
            payload['signature'] = sig
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Failed to sign handshake for {host}: {e}")
            return
        # Perform HTTP POST in a thread to avoid blocking the event loop
        import urllib.request
        import urllib.error
        import urllib.parse
        import json as _json
        def do_request(url: str, data: dict):
            body = _json.dumps(data).encode('utf-8')
            req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.getcode(), resp.read()
            except Exception as exc:
                return None, exc
        code, result = await asyncio.to_thread(do_request, handshake_url, payload)
        if code != 200:
            # Non-success status: pending or error
            if hasattr(self, 'logger'):
                self.logger.info(f"Handshake to {host} returned status {code}: {result}")
            return
        # Parse JSON reply
        try:
            resp_obj = json.loads(result.decode('utf-8'))
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Invalid handshake response from {host}: {e}")
            return
        # Verify response signature
        remote_host = resp_obj.get('from_host')
        remote_secret = resp_obj.get('secret')
        remote_sig = resp_obj.get('signature')
        if not (remote_host and remote_secret and remote_sig):
            if hasattr(self, 'logger'):
                self.logger.error(f"Malformed handshake response from {host}")
            return
        # Remove signature to verify
        base_resp = dict(resp_obj)
        base_resp.pop('signature', None)
        expected = self._sign_payload(self.bootstrap_secret, base_resp)
        if not hmac_compare(remote_sig, expected):
            if hasattr(self, 'logger'):
                self.logger.error(f"Handshake signature verification failed for {host}")
            return
        # Store remote secret
        try:
            self.db.set_link_secret(remote_host, remote_secret)
            if hasattr(self, 'logger'):
                self.logger.info(f"Handshake with {host} succeeded; stored secret for {remote_host}")
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Failed to store secret for {host}: {e}")
        return

    async def handshake_initiate_worker(self) -> None:
        """
        Iterate through all configured link hosts and initiate handshakes
        where necessary. This runs once at startup to automatically
        exchange secrets with peers using the bootstrap secret. Handshake
        requests with mismatched bootstrap secrets will result in a
        pending state and require manual approval via the SysOp console.
        """
        if not CONFIG or not CONFIG.has_section('link_hosts'):
            return
        hosts = CONFIG.options('link_hosts')
        for host in hosts:
            try:
                await self.initiate_handshake(host)
            except Exception as e:
                if hasattr(self, 'logger'):
                    self.logger.error(f"Handshake initiation failed for {host}: {e}")

    async def download_update(self, url: str) -> bool:
        """Download a new version of the script from the given URL.

        The current script file will be backed up with a .bak extension
        before being replaced. Returns True on success, False on failure.
        """
        if not url:
            return False
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = resp.read()
            script_path = os.path.realpath(__file__)
            backup_path = script_path + '.bak'
            shutil.copyfile(script_path, backup_path)
            with open(script_path, 'wb') as f:
                f.write(data)
            return True
        except Exception as e:
            # Log download error
            if hasattr(self, 'logger'):
                self.logger.error(f"Update download error: {e}")
            else:
                print(f"Update download error: {e}", file=sys.stderr)
            return False

    async def remote_worker(self) -> None:
        """Background task to process queued remote operations."""
        while True:
            try:
                # Sleep a bit to avoid busy loop
                await asyncio.sleep(self.remote_retry_interval)
                # Fetch due tasks
                tasks = self.db.get_due_remote_tasks(self.remote_retry_interval)
                for task in tasks:
                    task_id = task['id']
                    host = task['host']
                    endpoint = task['endpoint']
                    payload_json = task['payload']
                    op_type = task['op_type']
                    attempts = task['attempts']
                    max_attempts = task['max_attempts'] if task['max_attempts'] else self.remote_max_attempts
                    # Compose URL
                    base = None
                    if CONFIG and CONFIG.has_section('link_hosts'):
                        base = CONFIG.get('link_hosts', host, fallback=None)
                    if not base:
                        # Unknown host: mark failed
                        self.db.mark_remote_task_failed(task_id)
                        continue
                    # Skip sending to hosts marked as down. The [link_down] section
                    # contains host aliases and ISO timestamps. If a host is
                    # listed without a timestamp, it is considered down
                    # indefinitely. When a host is down, we simply leave the
                    # task in the queue until the downtime expires or the entry
                    # is removed. This prevents unnecessary errors and log
                    # messages during planned maintenance.
                    if CONFIG and CONFIG.has_section('link_down') and CONFIG.has_option('link_down', host):
                        down_val = CONFIG.get('link_down', host)
                        skip = False
                        if down_val:
                            try:
                                expiry = datetime.fromisoformat(down_val)
                                if datetime.utcnow() < expiry:
                                    skip = True
                            except Exception:
                                # Unparsable means indefinite
                                skip = True
                        else:
                            # Empty value indicates indefinite downtime
                            skip = True
                        if skip:
                            # Do not attempt delivery; move to next task
                            continue
                    url = base.rstrip('/') + endpoint
                    data = payload_json.encode('utf-8')
                    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                    loop = asyncio.get_running_loop()
                    try:
                        # Send in executor to avoid blocking
                        resp = await loop.run_in_executor(None, lambda req=req: urllib.request.urlopen(req, timeout=10))
                        # Try to parse response for protocol status
                        try:
                            data_bytes = resp.read()
                            if data_bytes:
                                resp_text = data_bytes.decode('utf-8', errors='ignore')
                                try:
                                    resp_json = json.loads(resp_text)
                                    # If remote host returns an error due to version mismatch or
                                    # unsupported protocol, mark as failed and notify
                                    if 'error' in resp_json:
                                        err = resp_json['error']
                                        if err in ('version_mismatch', 'unsupported_protocol'):
                                            self.db.mark_remote_task_failed(task_id)
                                            if self.remote_notify and hasattr(self, 'logger'):
                                                self.logger.error(f"Remote host {host} rejected task due to protocol mismatch: {err}")
                                            continue
                                except Exception:
                                    pass
                        except Exception:
                            # swallow response parsing errors
                            pass
                        # Success if we didn't mark as failed above
                        self.db.mark_remote_task_success(task_id)
                        # Bandwidth throttling: delay after file transfers
                        if op_type == 'file' and self.transfer_rate and self.transfer_rate > 0:
                            # Approximate size of the JSON payload in bytes
                            try:
                                payload_size = len(data)
                                delay = payload_size / float(self.transfer_rate)
                                if delay > 0:
                                    await asyncio.sleep(delay)
                            except Exception:
                                pass
                    except Exception as e:
                        # On error increment attempts
                        if attempts + 1 >= max_attempts:
                            # Mark failed and optionally notify
                            self.db.mark_remote_task_failed(task_id)
                            if self.remote_notify:
                                # Add an entry into moderation_log for SysOp notification
                                self.db.conn.execute('INSERT INTO moderation_log (moderator_id, target_type, target_id, action, info, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                                                    (0, 'remote', 0, 'failure', f'{op_type} to {host} failed: {e}', datetime.utcnow().isoformat()))
                                self.db.conn.commit()
                        else:
                            self.db.increment_remote_task_attempts(task_id)
                            # The worker will retry later
            except Exception as e:
                # Unexpected error in worker; log and continue
                if hasattr(self, 'logger'):
                    self.logger.error(f"Remote worker error: {e}")
                else:
                    print(f"Remote worker error: {e}", file=sys.stderr)

    # -----------------------------------------------------------------
    # Maintenance subsystem
    #
    async def maintenance_worker(self) -> None:
        """Background task that periodically expires and removes old posts/files.

        This coroutine runs indefinitely, sleeping for ``self.maintenance_interval``
        seconds between invocations of ``perform_maintenance()``. It catches
        exceptions to prevent the worker from terminating unexpectedly.
        """
        # Give the server time to start before the first maintenance run
        await asyncio.sleep(5)
        while True:
            await asyncio.sleep(self.maintenance_interval)
            try:
                await self.perform_maintenance()
            except Exception as e:
                # Log the maintenance error but continue the loop
                if hasattr(self, 'logger'):
                    self.logger.error(f"Maintenance error: {e}")
                else:
                    print(f"Maintenance error: {e}", file=sys.stderr)

    async def perform_maintenance(self) -> None:
        """Expire and delete old posts and files based on board/area settings.

        For each message board or file area with a positive ``max_age``, posts
        or files older than that age are marked expired (by setting
        ``expired_at``). Items already expired and older than
        ``self.maintenance_grace_days`` days are permanently removed along
        with any attachments or file data. This method executes synchronously
        on the database. If you anticipate very large datasets or slow
        operations, consider running the DB operations in a separate
        executor.
        """
        now = datetime.utcnow()
        # Expire posts per board
        for row in self.db.get_boards_with_max_age():
            board_id = row['id']
            max_age_days = row['max_age']
            if max_age_days and max_age_days > 0:
                cutoff = now - timedelta(days=max_age_days)
                self.db.expire_posts(board_id, cutoff)
        # Expire files per file area
        for row in self.db.get_file_areas_with_max_age():
            area_id = row['id']
            max_age_days = row['max_age']
            if max_age_days and max_age_days > 0:
                cutoff = now - timedelta(days=max_age_days)
                self.db.expire_files(area_id, cutoff)
        # Delete expired posts and files after grace period
        delete_cutoff = now - timedelta(days=self.maintenance_grace_days)
        self.db.delete_expired_posts(delete_cutoff)
        self.db.delete_expired_files(delete_cutoff)
        # Log maintenance completion
        if hasattr(self, 'logger'):
            self.logger.info('Maintenance completed')


###############################################################################
# Entry point
###############################################################################

def main() -> None:
    # Ensure database exists and there is at least one board
    bbs = BBS(HOST, TELNET_PORT, SSH_PORT)
    # Create a default board if none exist
    if not netbbsd.db.list_boards():
        netbbsd.db.add_board('General', 'General discussion')
    try:
        asyncio.run(bbs.start())
    except KeyboardInterrupt:
        print('Server shutting down.')


if __name__ == '__main__':
    main()