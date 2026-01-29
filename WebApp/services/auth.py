"""
Authentication and User Management Service

Provides secure user authentication with:
- Bcrypt password hashing with automatic salt
- SQLite database for user storage
- JWT token-based session management
- Rate limiting for login attempts
- Secure session cleanup
"""

import os
import sqlite3
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from contextlib import contextmanager

# Use bcrypt for password hashing (industry standard)
try:
    import bcrypt
except ImportError:
    bcrypt = None

# JWT for secure tokens
try:
    import jwt
except ImportError:
    jwt = None


@dataclass
class User:
    """User model"""
    id: int
    username: str
    password_hash: str
    created_at: str
    last_login: Optional[str] = None
    is_admin: bool = False


@dataclass
class AuthSession:
    """Authentication session"""
    token: str
    user_id: int
    username: str
    created_at: datetime
    expires_at: datetime
    data_sessions: list  # List of EFT processing session IDs owned by this user


class AuthManager:
    """Handles user authentication and session management"""

    # Password requirements
    MIN_PASSWORD_LENGTH = 8

    # Session settings
    SESSION_DURATION_HOURS = 2
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

    # JWT settings
    JWT_ALGORITHM = "HS256"

    def __init__(self, db_path: str = "/app/data/users.db", secret_key: Optional[str] = None):
        """Initialize auth manager with database path and secret key"""
        self.db_path = db_path

        # Generate or load secret key for JWT signing
        self.secret_key = secret_key or os.environ.get("AUTH_SECRET_KEY")
        if not self.secret_key:
            # Generate a secure random key if not provided
            key_file = os.path.join(os.path.dirname(db_path), ".secret_key")
            if os.path.exists(key_file):
                with open(key_file, "r") as f:
                    self.secret_key = f.read().strip()
            else:
                self.secret_key = secrets.token_hex(32)
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, "w") as f:
                    f.write(self.secret_key)
                os.chmod(key_file, 0o600)  # Restrict permissions

        # In-memory session store (for active sessions)
        self.active_sessions: Dict[str, AuthSession] = {}

        # Login attempt tracking for rate limiting
        self.login_attempts: Dict[str, list] = {}  # ip -> [(timestamp, success)]

        # Initialize database
        self._init_db()

    @contextmanager
    def _get_db(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initialize the database schema"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._get_db() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT
                )
            """)

            # User sessions table (for persistence across restarts)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            # Data sessions table (links EFT processing sessions to users)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS data_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            # Audit log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT
                )
            """)

            conn.commit()

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt with automatic salt"""
        if bcrypt is None:
            # Fallback to PBKDF2 if bcrypt not available
            salt = secrets.token_hex(16)
            hash_bytes = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return f"pbkdf2:{salt}:{hash_bytes.hex()}"

        # Use bcrypt (preferred)
        salt = bcrypt.gensalt(rounds=12)
        hash_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hash_bytes.decode('utf-8')

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        if password_hash.startswith("pbkdf2:"):
            # PBKDF2 fallback
            parts = password_hash.split(":")
            if len(parts) != 3:
                return False
            _, salt, stored_hash = parts
            check_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            ).hex()
            return secrets.compare_digest(check_hash, stored_hash)

        if bcrypt is None:
            return False

        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except Exception:
            return False

    def _generate_token(self, user_id: int, username: str) -> str:
        """Generate a secure JWT token"""
        now = datetime.utcnow()
        expires = now + timedelta(hours=self.SESSION_DURATION_HOURS)

        payload = {
            "user_id": user_id,
            "username": username,
            "iat": now.timestamp(),
            "exp": expires.timestamp(),
            "jti": secrets.token_hex(16)  # Unique token ID
        }

        if jwt is not None:
            return jwt.encode(payload, self.secret_key, algorithm=self.JWT_ALGORITHM)

        # Fallback: Simple signed token
        import json
        import hmac
        token_data = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{secrets.token_urlsafe(32)}.{signature}"

    def _hash_token(self, token: str) -> str:
        """Hash token for storage (don't store raw tokens)"""
        return hashlib.sha256(token.encode()).hexdigest()

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password meets security requirements"""
        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters"

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if not (has_upper and has_lower):
            return False, "Password must contain both uppercase and lowercase letters"
        if not has_digit:
            return False, "Password must contain at least one number"
        if not has_special:
            return False, "Password must contain at least one special character"

        return True, "Password is strong"

    def validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate username format"""
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 50:
            return False, "Username must be less than 50 characters"
        if not username[0].isalpha():
            return False, "Username must start with a letter"
        if not all(c.isalnum() or c in "_-" for c in username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"

        return True, "Username is valid"

    def check_rate_limit(self, ip_address: str) -> Tuple[bool, Optional[int]]:
        """Check if IP is rate limited. Returns (allowed, seconds_until_unlock)"""
        now = time.time()

        if ip_address not in self.login_attempts:
            return True, None

        # Clean old attempts (older than lockout duration)
        cutoff = now - (self.LOCKOUT_DURATION_MINUTES * 60)
        self.login_attempts[ip_address] = [
            (ts, success) for ts, success in self.login_attempts[ip_address]
            if ts > cutoff
        ]

        # Count recent failed attempts
        recent_failures = sum(
            1 for ts, success in self.login_attempts[ip_address]
            if not success
        )

        if recent_failures >= self.MAX_LOGIN_ATTEMPTS:
            # Find when the lockout expires
            oldest_failure = min(
                ts for ts, success in self.login_attempts[ip_address]
                if not success
            )
            unlock_time = oldest_failure + (self.LOCKOUT_DURATION_MINUTES * 60)
            remaining = int(unlock_time - now)
            if remaining > 0:
                return False, remaining

        return True, None

    def record_login_attempt(self, ip_address: str, success: bool):
        """Record a login attempt for rate limiting"""
        if ip_address not in self.login_attempts:
            self.login_attempts[ip_address] = []

        self.login_attempts[ip_address].append((time.time(), success))

        # Clear on successful login
        if success:
            self.login_attempts[ip_address] = [
                (ts, s) for ts, s in self.login_attempts[ip_address]
                if s  # Keep only successes
            ]

    def create_user(self, username: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
        """Create a new user account"""
        # Validate username
        valid, msg = self.validate_username(username)
        if not valid:
            return False, msg

        # Validate password
        valid, msg = self.validate_password_strength(password)
        if not valid:
            return False, msg

        # Hash password
        password_hash = self._hash_password(password)

        try:
            with self._get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username.lower(), password_hash, 1 if is_admin else 0)
                )
                conn.commit()
                return True, "User created successfully"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, f"Error creating user: {str(e)}"

    def authenticate(self, username: str, password: str, ip_address: str = "",
                    user_agent: str = "") -> Tuple[bool, str, Optional[str]]:
        """
        Authenticate user and create session.
        Returns (success, message, token)
        """
        # Check rate limit
        allowed, wait_time = self.check_rate_limit(ip_address)
        if not allowed:
            return False, f"Too many failed attempts. Try again in {wait_time} seconds.", None

        username = username.lower().strip()

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password_hash, is_admin, locked_until FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()

            if not row:
                self.record_login_attempt(ip_address, False)
                return False, "Invalid username or password", None

            user_id, db_username, password_hash, is_admin, locked_until = row

            # Check if account is locked
            if locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.utcnow() < lock_time:
                    remaining = int((lock_time - datetime.utcnow()).total_seconds())
                    return False, f"Account locked. Try again in {remaining} seconds.", None

            # Verify password
            if not self._verify_password(password, password_hash):
                self.record_login_attempt(ip_address, False)

                # Update failed attempts in database
                cursor.execute(
                    "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                    (user_id,)
                )

                # Lock account after too many failures
                cursor.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
                failed_count = cursor.fetchone()[0]
                if failed_count >= self.MAX_LOGIN_ATTEMPTS:
                    lock_until = datetime.utcnow() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)
                    cursor.execute(
                        "UPDATE users SET locked_until = ? WHERE id = ?",
                        (lock_until.isoformat(), user_id)
                    )

                conn.commit()
                return False, "Invalid username or password", None

            # Successful login
            self.record_login_attempt(ip_address, True)

            # Reset failed attempts
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), user_id)
            )

            # Generate token
            token = self._generate_token(user_id, db_username)

            # Store session in database
            now = datetime.utcnow()
            expires = now + timedelta(hours=self.SESSION_DURATION_HOURS)
            cursor.execute(
                """INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, ip_address, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (self._hash_token(token), user_id, now.isoformat(), expires.isoformat(),
                 ip_address, user_agent[:500] if user_agent else None)
            )

            # Log the login
            cursor.execute(
                "INSERT INTO audit_log (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
                (user_id, "LOGIN", ip_address, user_agent[:500] if user_agent else None)
            )

            conn.commit()

            # Create in-memory session
            self.active_sessions[token] = AuthSession(
                token=token,
                user_id=user_id,
                username=db_username,
                created_at=now,
                expires_at=expires,
                data_sessions=[]
            )

            return True, "Login successful", token

    def validate_token(self, token: str) -> Optional[AuthSession]:
        """Validate a token and return the session if valid"""
        if not token:
            return None

        # Check in-memory cache first
        if token in self.active_sessions:
            session = self.active_sessions[token]
            if datetime.utcnow() < session.expires_at:
                return session
            else:
                # Expired, remove from cache
                del self.active_sessions[token]

        # Check database
        token_hash = self._hash_token(token)
        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT s.user_id, u.username, s.created_at, s.expires_at
                   FROM user_sessions s
                   JOIN users u ON s.user_id = u.id
                   WHERE s.token_hash = ?""",
                (token_hash,)
            )
            row = cursor.fetchone()

            if not row:
                return None

            user_id, username, created_at, expires_at = row
            expires = datetime.fromisoformat(expires_at)

            if datetime.utcnow() >= expires:
                # Expired, clean up
                cursor.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
                conn.commit()
                return None

            # Load data sessions for this user
            cursor.execute(
                "SELECT session_id FROM data_sessions WHERE user_id = ?",
                (user_id,)
            )
            data_sessions = [row[0] for row in cursor.fetchall()]

            # Restore to cache
            session = AuthSession(
                token=token,
                user_id=user_id,
                username=username,
                created_at=datetime.fromisoformat(created_at),
                expires_at=expires,
                data_sessions=data_sessions
            )
            self.active_sessions[token] = session

            return session

    def logout(self, token: str, ip_address: str = "") -> bool:
        """Invalidate a session"""
        if token in self.active_sessions:
            session = self.active_sessions[token]
            del self.active_sessions[token]

            with self._get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM user_sessions WHERE token_hash = ?",
                    (self._hash_token(token),)
                )
                cursor.execute(
                    "INSERT INTO audit_log (user_id, action, ip_address) VALUES (?, ?, ?)",
                    (session.user_id, "LOGOUT", ip_address)
                )
                conn.commit()

            return True

        # Try database
        token_hash = self._hash_token(token)
        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM user_sessions WHERE token_hash = ?", (token_hash,))
            row = cursor.fetchone()
            if row:
                cursor.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash,))
                cursor.execute(
                    "INSERT INTO audit_log (user_id, action, ip_address) VALUES (?, ?, ?)",
                    (row[0], "LOGOUT", ip_address)
                )
                conn.commit()
                return True

        return False

    def register_data_session(self, auth_token: str, session_id: str) -> bool:
        """Register a data processing session to a user"""
        session = self.validate_token(auth_token)
        if not session:
            return False

        with self._get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO data_sessions (session_id, user_id) VALUES (?, ?)",
                    (session_id, session.user_id)
                )
                conn.commit()
                session.data_sessions.append(session_id)
                return True
            except sqlite3.IntegrityError:
                return False

    def owns_data_session(self, auth_token: str, session_id: str) -> bool:
        """Check if user owns a data processing session"""
        session = self.validate_token(auth_token)
        if not session:
            return False

        # Check cache
        if session_id in session.data_sessions:
            return True

        # Check database
        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM data_sessions WHERE session_id = ? AND user_id = ?",
                (session_id, session.user_id)
            )
            return cursor.fetchone() is not None

    def get_user_data_sessions(self, auth_token: str) -> list:
        """Get all data sessions for a user"""
        session = self.validate_token(auth_token)
        if not session:
            return []

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT session_id, created_at, last_accessed FROM data_sessions WHERE user_id = ?",
                (session.user_id,)
            )
            return [
                {"session_id": row[0], "created_at": row[1], "last_accessed": row[2]}
                for row in cursor.fetchall()
            ]

    def delete_user_data_sessions(self, auth_token: str) -> int:
        """Delete all data sessions for a user. Returns count deleted."""
        session = self.validate_token(auth_token)
        if not session:
            return 0

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT session_id FROM data_sessions WHERE user_id = ?",
                (session.user_id,)
            )
            sessions = [row[0] for row in cursor.fetchall()]

            cursor.execute(
                "DELETE FROM data_sessions WHERE user_id = ?",
                (session.user_id,)
            )

            cursor.execute(
                "INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)",
                (session.user_id, "DELETE_ALL_DATA", f"Deleted {len(sessions)} sessions")
            )

            conn.commit()

            # Clear from cache
            session.data_sessions = []

            return len(sessions)

    def cleanup_expired_sessions(self):
        """Clean up expired sessions from database"""
        now = datetime.utcnow().isoformat()

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM user_sessions WHERE expires_at < ?",
                (now,)
            )
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    def change_password(self, auth_token: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password"""
        session = self.validate_token(auth_token)
        if not session:
            return False, "Invalid session"

        # Validate new password
        valid, msg = self.validate_password_strength(new_password)
        if not valid:
            return False, msg

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (session.user_id,)
            )
            row = cursor.fetchone()

            if not row or not self._verify_password(old_password, row[0]):
                return False, "Current password is incorrect"

            # Update password
            new_hash = self._hash_password(new_password)
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, session.user_id)
            )

            # Invalidate all other sessions
            cursor.execute(
                "DELETE FROM user_sessions WHERE user_id = ? AND token_hash != ?",
                (session.user_id, self._hash_token(auth_token))
            )

            cursor.execute(
                "INSERT INTO audit_log (user_id, action) VALUES (?, ?)",
                (session.user_id, "PASSWORD_CHANGE")
            )

            conn.commit()

            return True, "Password changed successfully"

    def get_user_count(self) -> int:
        """Get total number of users"""
        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0]

    def log_action(self, auth_token: str, action: str, details: str = "",
                   ip_address: str = "", user_agent: str = ""):
        """Log an action to the audit log"""
        session = self.validate_token(auth_token)
        user_id = session.user_id if session else None

        with self._get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO audit_log (user_id, action, details, ip_address, user_agent)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, action, details[:1000] if details else None,
                 ip_address, user_agent[:500] if user_agent else None)
            )
            conn.commit()
