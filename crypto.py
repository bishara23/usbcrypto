import hashlib
import os
import base64
import json
import ctypes
import time
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .derive_key import derive_key


class USBManager:
    DRIVE_REMOVABLE = 2  # Windows constant for removable media

    @staticmethod
    def alert_access_granted(drive: str,
                             title: str = "USB Security",
                             message: str = "✅ Access Granted!\nAll files have been decrypted and verified."):
        ctypes.windll.user32.MessageBoxW(None, message, title, 0)

    @staticmethod
    def alert_and_disable(drive: str,
                          title: str = "USB Security Alert",
                          message: str = "⚠️ USB device disabled due to invalid signature."):
        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
        subprocess.run(f"mountvol {drive} /p", shell=True)
        sys.exit(1)

    @staticmethod
    def find_usb_drive(timeout: float = 10.0, interval: float = 0.5) -> str:
        # figure out your system drive (e.g. "C:\")
        system_drive = os.environ.get("SystemDrive", "C:").upper() + "\\"
        deadline = time.time() + timeout

        while time.time() < deadline:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    drive = f"{chr(65 + i)}:\\"
                    dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
                    print(f"🧪 Checking {drive} → type {dtype}")
                    # 1) True removable media (type 2), 2) Fixed but not the system drive (type 3)
                    if ((dtype == USBManager.DRIVE_REMOVABLE) or (dtype == 3)) and drive != system_drive:
                        return drive
            time.sleep(interval)

        raise RuntimeError("No removable or fixed USB drive found (timed out)")



class Decryptor(object):
    def strip_signature(self, file_path: str):
        """
        Removes the first 32 bytes (signature) from the file if the signature is valid.
        """
        with open(file_path, 'rb') as f:
            file_data = f.read()
        with open(file_path, 'wb') as f:
            f.write(file_data[32:])

    def decrypt_file_raw(self, input_path, output_path, key: bytes, iv: bytes):
        with open(input_path, "rb") as f:
            ciphertext = f.read()

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)

        with open(output_path, "wb") as f:
            f.write(plaintext)

    def decrypt_all_in_folder(self, folder_path: str, password: str):
        metadata_path = folder_path + '/metadata.json'
        if not os.path.exists(metadata_path):
            print("❌ metadata.json not found!")
            drive = Path(folder_path).anchor.rstrip("\\")
            USBManager.alert_and_disable(drive)

        with open(metadata_path, "r") as f:
            try:
                metadata = json.load(f)
            except json.JSONDecodeError:
                print("❌ metadata.json is corrupted!")
                drive = Path(folder_path).anchor.rstrip("\\")
                USBManager.alert_and_disable(drive)

        # ── Detect any unauthorized (new) files ────────────────────────────
        actual = set()
        for root, dirs, files in os.walk(folder_path, topdown=True):
            # skip system folders
            dirs[:] = [
                d for d in dirs
                if d.lower() not in ('system volume information', '$recycle.bin')
            ]
            for fn in files:
                # ignore the metadata file itself
                if fn == 'metadata.json':
                    continue
                rel = os.path.relpath(os.path.join(root, fn), folder_path)
                actual.add(rel)

        extra = actual - set(metadata.keys())
        if extra:
            drive = Path(folder_path).anchor.rstrip("\\")
            USBManager.alert_and_disable(
                drive,
                message=(
                    "⚠️ Unauthorized files detected:\n"
                    + "\n".join(f" • {e}" for e in sorted(extra))
                )
            )
        # ── End new-file check ─────────────────────────────────────────────

        valid_files = 0
        total_files = 0

        for rel_path, data in metadata.items():
            # ── skip Windows’ protected system folder ──────────────────────────
            if rel_path.lower().startswith("system volume information"):
                continue
            full_path = os.path.join(folder_path, rel_path)

            salt = base64.b64decode(data["salt"])
            iv = base64.b64decode(data["iv"])
            kdf_type = data.get("kdf", "argon2id")

            if kdf_type != "argon2id":
                print(f"❌ Unsupported KDF type: {kdf_type}")
                continue

            key = derive_key(password, salt)

            try:
                self.decrypt_file_raw(full_path, full_path, key, iv)
                total_files += 1

                # verify signature and handle invalid case
                if self.verify_signed_file(full_path):
                    self.strip_signature(full_path)
                    valid_files += 1
                else:
                    drive = Path(folder_path).anchor.rstrip("\\")
                    USBManager.alert_and_disable(drive)

            except Exception as e:
                print(f"❌ Failed to decrypt {rel_path}: {e}")
                drive = Path(folder_path).anchor.rstrip("\\")
                USBManager.alert_and_disable(drive)

        drive = Path(folder_path).anchor.rstrip("\\")
        if valid_files == total_files and total_files > 0:
            print("✅ All files decrypted and verified!")
            USBManager.alert_access_granted(drive)
        else:
            USBManager.alert_and_disable(drive)


    def verify_signed_file(self, file_path: str) -> bool:
        """
        Verifies the SHA3-256 signature of a file.
        Assumes the first 32 bytes are the original hash,
        and the rest is the file content.

        Parameters:
            file_path (str): Path to the signed file.

        Returns:
            bool: True if the signature matches, False otherwise.
        """
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()

            if len(file_data) < 32:
                print(f"⚠️ File too short to contain a valid signature: {file_path}")
                return False

            original_hash = file_data[:32]
            content = file_data[32:]
            computed_hash = hashlib.sha3_256(content).digest()

            if computed_hash == original_hash:
                print(f"✅ Valid signature: {file_path}")
                return True
            else:
                print(f"❌ Invalid signature: {file_path}")
                return False

        except Exception as e:
            print(f"❌ Error verifying file {file_path}: {e}")
            return False

class Encryptor(object):
    def generate_sha3_signature_with_content(self, file_path: str) -> bytes:
        """
        Generates a SHA-3 (256-bit) hash for a file and concatenates it with the file's content.

        Parameters:
            file_path (str): The path to the file.

        Returns:
            bytes: The concatenated result of the hash and the file's content.
        """
        sha3_hash = hashlib.sha3_256()  # Create an SHA-3 (256-bit) hash object

        # Read the file and update the hash
        with open(file_path, 'rb') as file:
            file_content = file.read()  # Read the entire file content
            sha3_hash.update(file_content)  # Update the hash object with the file content

        # Generate the digest and concatenate it with the file content
        result = sha3_hash.digest() + file_content
        return result

    def sign_all_files_in_folder(self, path: str):
        for root, dirs, files in os.walk(path, topdown=True):
            # ── prune out Windows’ hidden system folders ────────────────────────
            dirs[:] = [d for d in dirs
                       if d.lower() not in ('system volume information', '$recycle.bin')]
            for file_name in files:
                file_path = os.path.join(root, file_name)  # Full path to the file

                try:
                    # Generate hash concatenated with file content
                    combined_data = self.generate_sha3_signature_with_content(file_path)
                    #print(f"First 32 bytes (hash): {combined_data[:32]}")
                    #print(f"Rest of the data (file content): {combined_data[32:]}")
                    # Write the combined data back to the same file
                    with open(file_path, 'wb') as file:
                        file.write(combined_data)

                    print(f"Processed file: {file_path}")
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")

    def encrypt_file_raw(self, input_path, output_path, key: bytes, iv: bytes):
        with open(input_path, "rb") as f:
            plaintext = f.read()

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        with open(output_path, "wb") as f:
            f.write(ciphertext)

    def encrypt_all_in_folder(self, folder_path: str, password: str):
        metadata_path = folder_path + '/metadata.json'
        metadata = {}

        for root, dirs, files in os.walk(folder_path, topdown=True):
            # ── prune out Windows’ hidden system folders ────────────────────────
            dirs[:] = [d for d in dirs
                       if d.lower() not in ('system volume information', '$recycle.bin')]
            for filename in files:
                full_path = os.path.join(root, filename)

                # dont encrypt metadata file
                if os.path.abspath(full_path) == os.path.abspath(metadata_path):
                    continue

                # relative path in folder
                rel_path = os.path.relpath(full_path, folder_path)

                print(f"🔐 Encrypting: {rel_path}")

                # salt and IV creation
                salt = os.urandom(16)
                iv = os.urandom(12)

                key = derive_key(password, salt)

                self.encrypt_file_raw(full_path, full_path, key, iv)

                metadata[rel_path] = {
                    "salt": base64.b64encode(salt).decode(),
                    "iv": base64.b64encode(iv).decode(),
                    "kdf": "argon2id"
                }

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)

        print(f"✅ Metadata saved to: {metadata_path}")
