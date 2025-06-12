import os
import json
import base64
import sqlite3
import re
import win32crypt
from urllib.parse import unquote
from Crypto.Cipher import AES
import sys
from collections import defaultdict
import time
import subprocess

# Paths - MODIFY IF USING DIFFERENT PROFILE
USER_PROFILE = os.environ['USERPROFILE']
LOCAL_STATE_PATH = os.path.join(USER_PROFILE, 
                              r'AppData\Local\Google\Chrome\User Data\Local State')
COOKIES_PATH = os.path.join(USER_PROFILE,
                          r'AppData\Local\Google\Chrome\User Data\Default\Network\Cookies')

def print_banner():
    print("=" * 60)
    print("         Chrome Cookie Decryption Tool")
    print("=" * 60)
    print("This tool will safely decrypt and display your Chrome cookies.")
    print("All processing is done locally on your machine.\n")

def check_prerequisites():
    print("[!] Checking prerequisites...")

    # Check for Chrome processes and kill them
    tasks = subprocess.check_output("tasklist", shell=True).decode()
    if "chrome.exe" in tasks:
        print("[!] Chrome is running. Attempting to terminate it...")
        subprocess.call("taskkill /F /IM chrome.exe", shell=True)
        time.sleep(2)
        print("[+] Chrome terminated")

    if not os.path.exists(LOCAL_STATE_PATH):
        print("[-] Chrome Local State file not found!")
        print(f"   Expected location: {LOCAL_STATE_PATH}")
        return False

    if not os.path.exists(COOKIES_PATH):
        print("[-] Chrome Cookies database not found!")
        print(f"   Expected location: {COOKIES_PATH}")
        return False

    print("[+] Chrome files found")
    return True

def get_master_key():
    print("[!] Extracting master encryption key...")
    try:
        with open(LOCAL_STATE_PATH, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        if encrypted_key.startswith(b'DPAPI'):
            encrypted_key = encrypted_key[5:]
        key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        print("[+] Master key extracted successfully")
        return key
    except Exception as e:
        raise RuntimeError(f"Failed to extract encryption key: {str(e)}")

def is_json(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    if (value.startswith('{') and value.endswith('}')) or (value.startswith('[') and value.endswith(']')):
        try:
            json.loads(value)
            return True
        except ValueError:
            return False
    return False

def unwrap_json_cookie(raw_value):
    if is_json(raw_value):
        try:
            parsed = json.loads(raw_value)
            if isinstance(parsed, dict) and 'value' in parsed:
                return parsed['value']
        except json.JSONDecodeError:
            pass
    return raw_value

def categorize_cookie(name):
    name_lower = name.lower()
    if 'auth' in name_lower:
        return 'AUTH'
    elif 'session' in name_lower:
        return 'SESSION'
    elif 'token' in name_lower or 'jwt' in name_lower:
        return 'TOKEN'
    elif 'id' in name_lower or 'uid' in name_lower:
        return 'IDENTIFIER'
    elif 'consent' in name_lower or 'gdpr' in name_lower:
        return 'CONSENT'
    else:
        return 'OTHER'

def decode_cookie_value(value):
    try:
        decoded = value.decode('utf-8')
        if '%' in decoded:
            return unquote(decoded)
        return decoded
    except UnicodeDecodeError:
        return value.decode('utf-8', errors='replace')

def decrypt_value(encrypted_value, key):
    if not encrypted_value:
        return "[EMPTY]"
    try:
        if not encrypted_value.startswith(b'v10'):
            return decode_cookie_value(encrypted_value)
        nonce = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        decoded = decode_cookie_value(decrypted)
        return unwrap_json_cookie(decoded)
    except Exception as e:
        return f"[DECRYPT FAILED: {str(e)}]"

def clean_output(host, name, value):
    host_clean = host.decode().strip()
    name_clean = name.decode().strip()
    if value in ("[EMPTY]", "[NON-ENCRYPTED]"):
        return f"=> {host_clean} | {name_clean} = {value}\n"
    if is_json(value):
        try:
            json_data = json.loads(value)
            json_str = json.dumps(json_data, indent=2)
            return f"=> {host_clean} | {name_clean} = (JSON)\n{json_str}\n"
        except:
            pass
    return f"=> {host_clean} | {name_clean} = {value}\n"

def decrypt_cookies(master_key):
    print("[!] Starting cookie decryption process...")
    conn = None
    stats = defaultdict(int)
    processed_count = 0
    all_cookies = defaultdict(list)

    try:
        conn = sqlite3.connect(COOKIES_PATH)
        conn.text_factory = bytes
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cookies")
        total_cookies = cursor.fetchone()[0]

        print(f"[!] Found {total_cookies} cookies to process")
        print("\n" + "=" * 60)
        print("     DECRYPTED COOKIES:")
        print("=" * 60)

        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")

        for host, name, encrypted_value in cursor.fetchall():
            processed_count += 1
            decrypted = decrypt_value(encrypted_value, master_key)
            category = categorize_cookie(name.decode())
            stats[category] += 1
            formatted = clean_output(host, name, decrypted)
            all_cookies[category].append(formatted)
            print(formatted)

            if processed_count % 50 == 0:
                print(f"\n[*] Progress: {processed_count}/{total_cookies} cookies processed...\n")

        print("\n" + "=" * 60)
        print("[+] SUMMARY STATISTICS:")
        print("=" * 60)
        for cat, count in sorted(stats.items()):
            print(f"  {cat}: {count}")
        print(f"  [+] TOTAL PROCESSED: {sum(stats.values())}")
        print("=" * 60)

        while True:
            selection = input("\n[?] Enter category to view (AUTH, SESSION, TOKEN, IDENTIFIER, CONSENT, OTHER, ALL, EXIT): ").strip().upper()
            if selection == "EXIT":
                break
            print("\n" + "=" * 60)
            print(f"  DISPLAYING: {selection} cookies")
            print("=" * 60)

            if selection == "ALL":
                for cat in all_cookies:
                    for line in all_cookies[cat]:
                        print(line)
            elif selection in all_cookies:
                for line in all_cookies[selection]:
                    print(line)
            else:
                print("[!] Invalid category selection. Try again or type EXIT to quit.")

    except Exception as e:
        print(f"[-] Database error: {str(e)}")
        print("[!] Make sure Chrome is completely closed and try again")
    finally:
        if conn:
            conn.close()

def main():
    try:
        print_banner()
        if not check_prerequisites():
            print("\n❌ Prerequisites check failed. Please resolve the issues above.")
            input("\nPress Enter to exit...")
            return
        print("\n[+] Starting decryption process...")
        time.sleep(1)
        master_key = get_master_key()
        print(f"[+] Master Key Length: {len(master_key)} bytes")
        print("\n" + "=" * 65)
        print("  IMPORTANT: The following data contains sensitive information")
        print("  Please handle with care and do not share publicly")
        print("=" * 65)
        input("\nPress Enter to continue with cookie decryption...")
        decrypt_cookies(master_key)
        print("\n[!] Cookie decryption completed successfully!")
        print("[+] Tip: You can scroll up to review all the decrypted cookies")
    except KeyboardInterrupt:
        print("\n\n[-]  Process interrupted by user")
    except Exception as e:
        print(f"\n[-] Critical Error: {str(e)}")
        print("[*] Common solutions:")
        print("   • Make sure Chrome is completely closed")
        print("   • Run as administrator if needed")
        print("   • Check if antivirus is blocking access")
    finally:
        print("\n" + "=" * 60)
        print("Thank you for using Chrome Cookie Decryption Tool!")
        print("=" * 60)
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
