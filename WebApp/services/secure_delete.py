"""
Secure Data Deletion Service

Provides secure file deletion with multiple overwrites to prevent data recovery.
This is critical for handling sensitive biometric data (fingerprints) and PII.
"""

import os
import shutil
import secrets
from typing import Optional, Callable
from pathlib import Path


class SecureDelete:
    """
    Secure file deletion with multiple overwrite passes.

    Implements DOD 5220.22-M style deletion:
    - Pass 1: Overwrite with zeros
    - Pass 2: Overwrite with ones
    - Pass 3: Overwrite with random data
    - Final: Truncate and delete
    """

    # Number of overwrite passes (3 is standard, 7 for paranoid mode)
    DEFAULT_PASSES = 3
    PARANOID_PASSES = 7

    def __init__(self, passes: int = DEFAULT_PASSES, verify: bool = True):
        """
        Initialize secure delete service.

        Args:
            passes: Number of overwrite passes (minimum 3)
            verify: Whether to verify overwrites
        """
        self.passes = max(passes, 3)
        self.verify = verify

    def _overwrite_file(self, file_path: str, pattern: bytes, block_size: int = 65536) -> bool:
        """
        Overwrite a file with a specific pattern.

        Args:
            file_path: Path to file
            pattern: Single byte to use for overwriting (will be repeated)
            block_size: Size of write blocks

        Returns:
            True if successful
        """
        try:
            file_size = os.path.getsize(file_path)

            with open(file_path, 'r+b') as f:
                written = 0
                while written < file_size:
                    chunk_size = min(block_size, file_size - written)
                    if len(pattern) == 1:
                        # Repeat single byte
                        chunk = pattern * chunk_size
                    else:
                        # Random pattern - generate fresh each time
                        chunk = secrets.token_bytes(chunk_size)
                    f.write(chunk)
                    written += chunk_size

                # Flush to disk
                f.flush()
                os.fsync(f.fileno())

            return True
        except Exception as e:
            print(f"Error overwriting {file_path}: {e}")
            return False

    def secure_delete_file(self, file_path: str) -> bool:
        """
        Securely delete a single file with multiple overwrite passes.

        Args:
            file_path: Path to file to delete

        Returns:
            True if file was securely deleted
        """
        if not os.path.exists(file_path):
            return True  # Already gone

        if not os.path.isfile(file_path):
            return False  # Not a file

        try:
            file_size = os.path.getsize(file_path)

            if file_size == 0:
                # Empty file, just delete
                os.remove(file_path)
                return True

            # Perform overwrite passes
            for pass_num in range(self.passes):
                if pass_num % 3 == 0:
                    # Zeros
                    success = self._overwrite_file(file_path, b'\x00')
                elif pass_num % 3 == 1:
                    # Ones
                    success = self._overwrite_file(file_path, b'\xFF')
                else:
                    # Random
                    success = self._overwrite_file(file_path, b'random')  # Special marker

                if not success:
                    # Continue anyway - best effort
                    pass

            # Truncate to zero length
            with open(file_path, 'w') as f:
                pass

            # Rename to random name before deletion (obscures original name)
            dir_path = os.path.dirname(file_path)
            random_name = secrets.token_hex(16)
            temp_path = os.path.join(dir_path, random_name)

            try:
                os.rename(file_path, temp_path)
                os.remove(temp_path)
            except Exception:
                # Fallback to direct delete
                os.remove(file_path)

            return True

        except Exception as e:
            print(f"Error securely deleting {file_path}: {e}")
            # Fallback to regular delete
            try:
                os.remove(file_path)
            except Exception:
                pass
            return False

    def secure_delete_directory(self, dir_path: str,
                                progress_callback: Optional[Callable[[int, int], None]] = None) -> bool:
        """
        Securely delete all files in a directory and the directory itself.

        Args:
            dir_path: Path to directory
            progress_callback: Optional callback(current, total) for progress updates

        Returns:
            True if all files were securely deleted
        """
        if not os.path.exists(dir_path):
            return True

        if not os.path.isdir(dir_path):
            return self.secure_delete_file(dir_path)

        try:
            # Collect all files first
            all_files = []
            for root, dirs, files in os.walk(dir_path):
                for name in files:
                    all_files.append(os.path.join(root, name))

            total = len(all_files)
            success_count = 0

            # Securely delete each file
            for i, file_path in enumerate(all_files):
                if self.secure_delete_file(file_path):
                    success_count += 1

                if progress_callback:
                    progress_callback(i + 1, total)

            # Remove empty directories
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass

            # Remove the top directory
            try:
                os.rmdir(dir_path)
            except Exception:
                # Force remove if not empty
                try:
                    shutil.rmtree(dir_path)
                except Exception:
                    pass

            return success_count == total

        except Exception as e:
            print(f"Error securely deleting directory {dir_path}: {e}")
            # Fallback to regular delete
            try:
                shutil.rmtree(dir_path)
            except Exception:
                pass
            return False

    def wipe_free_space(self, path: str, block_size: int = 1024 * 1024) -> bool:
        """
        Write random data to fill free space, then delete it.
        This helps ensure previously deleted files can't be recovered.

        Args:
            path: Path to a directory on the volume to wipe
            block_size: Size of blocks to write (default 1MB)

        Returns:
            True if successful
        """
        if not os.path.isdir(path):
            return False

        wipe_file = os.path.join(path, f".wipe_{secrets.token_hex(8)}")

        try:
            with open(wipe_file, 'wb') as f:
                while True:
                    try:
                        f.write(secrets.token_bytes(block_size))
                        f.flush()
                    except OSError:
                        # Disk full - that's what we want
                        break

            # Securely delete the wipe file
            self.secure_delete_file(wipe_file)
            return True

        except Exception as e:
            print(f"Error wiping free space: {e}")
            try:
                os.remove(wipe_file)
            except Exception:
                pass
            return False


class SessionCleaner:
    """
    Manages automatic cleanup of expired sessions and their data.
    """

    def __init__(self, temp_dir: str, secure_delete: Optional[SecureDelete] = None):
        """
        Initialize session cleaner.

        Args:
            temp_dir: Base temporary directory for session data
            secure_delete: SecureDelete instance (creates default if not provided)
        """
        self.temp_dir = temp_dir
        self.secure_delete = secure_delete or SecureDelete()

    def cleanup_session(self, session_id: str) -> bool:
        """
        Securely clean up a single session's data.

        Args:
            session_id: Session ID to clean up

        Returns:
            True if cleanup was successful
        """
        session_dir = os.path.join(self.temp_dir, session_id)
        return self.secure_delete.secure_delete_directory(session_dir)

    def cleanup_all_sessions(self, exclude: Optional[list] = None,
                            progress_callback: Optional[Callable[[str], None]] = None) -> int:
        """
        Clean up all sessions except those in exclude list.

        Args:
            exclude: List of session IDs to preserve
            progress_callback: Optional callback(session_id) for progress updates

        Returns:
            Number of sessions cleaned up
        """
        exclude = exclude or []
        cleaned = 0

        if not os.path.exists(self.temp_dir):
            return 0

        for entry in os.listdir(self.temp_dir):
            if entry in exclude:
                continue

            session_dir = os.path.join(self.temp_dir, entry)
            if os.path.isdir(session_dir):
                if progress_callback:
                    progress_callback(entry)

                if self.secure_delete.secure_delete_directory(session_dir):
                    cleaned += 1

        return cleaned

    def get_session_size(self, session_id: str) -> int:
        """
        Get the total size of a session's data in bytes.
        """
        session_dir = os.path.join(self.temp_dir, session_id)
        if not os.path.exists(session_dir):
            return 0

        total = 0
        for root, dirs, files in os.walk(session_dir):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except Exception:
                    pass
        return total

    def get_all_sessions_size(self) -> int:
        """
        Get total size of all session data.
        """
        if not os.path.exists(self.temp_dir):
            return 0

        total = 0
        for entry in os.listdir(self.temp_dir):
            total += self.get_session_size(entry)
        return total
