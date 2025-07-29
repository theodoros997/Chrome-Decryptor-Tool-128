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
import argparse
from hashlib import sha1
import hmac
from dpapick3.blob import DPAPIBlob 

# Paths - MODIFY IF USING DIFFERENT PROFILE
USER_PROFILE = os.environ['USERPROFILE']
DEFAULT_LOCAL_STATE_PATH = os.path.join(USER_PROFILE, 
                                      r'AppData\Local\Google\Chrome\User Data\Local State')
DEFAULT_COOKIES_PATH = os.path.join(USER_PROFILE,
                                  r'AppData\Local\Google\Chrome\User Data\Default\Network\Cookies')

def print_banner():
    print("=" * 60)
    print("         Chrome Cookie Decryption Tool")
    print("=" * 60)
    print("This tool will safely decrypt and display your Chrome cookies.")
    print("All processing is done locally on your machine.\n")

def check_prerequisites(cookies_path):
    print("[!] Checking prerequisites...")

    # Check for Chrome processes and kill them
    tasks = subprocess.check_output("tasklist", shell=True).decode()
    if "chrome.exe" in tasks:
        print("[!] Chrome is running. Attempting to terminate it...")
        subprocess.call("taskkill /F /IM chrome.exe", shell=True)
        time.sleep(2)
        print("[+] Chrome terminated")

    if not os.path.exists(cookies_path):
        print("[-] Chrome Cookies database not found!")
        print(f"   Expected location: {cookies_path}")
        return False

    print("[+] Chrome files found")
    return True

def derive_chrome_key_from_dpapi_masterkey(dpapi_masterkey_hex, local_state_path):
    """Properly decrypt DPAPI-encrypted Chrome key from Local State using dpapick3"""
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            state = json.load(f)
        b64_encrypted_key = state['os_crypt']['encrypted_key']
        encrypted_blob = base64.b64decode(b64_encrypted_key)

        if encrypted_blob.startswith(b'DPAPI'):
            encrypted_blob = encrypted_blob[5:]

        blob = DPAPIBlob(encrypted_blob)
        success = blob.decrypt(masterkey=bytes.fromhex(dpapi_masterkey_hex))
        if not success:
            raise RuntimeError("DPAPI decryption failed — likely wrong master key or incompatible blob")

        return blob.cleartext[:32]
    except Exception as e:
        raise RuntimeError(f"[!] Failed to decrypt Chrome master key: {str(e)}")

def derive_chrome_key_from_guid_password(guid, password_sha1, local_state_path):
    """Derive Chrome key using DPAPI GUID and password SHA1"""
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            state = json.load(f)
        
        b64_encrypted_key = state['os_crypt']['encrypted_key']
        encrypted_key = base64.b64decode(b64_encrypted_key)
        
        if encrypted_key.startswith(b'DPAPI'):
            encrypted_key = encrypted_key[5:]
        
        salt = encrypted_key[36:52]
        combined = guid.encode() + bytes.fromhex(password_sha1)
        derived_key = hmac.new(salt, combined, sha1).digest()[:32]
        
        return derived_key
    
    except Exception as e:
        raise RuntimeError(f"GUID+Password derivation failed: {str(e)}")

def get_chrome_master_key(args):
    """Get master key based on input method"""
    if args.chrome_master_key:
        print("[+] Using direct Chrome master key")
        return bytes.fromhex(args.chrome_master_key)
    
    elif args.dpapi_master_key:
        print("[+] Deriving from DPAPI master key")
        return derive_chrome_key_from_dpapi_masterkey(
            args.dpapi_master_key,
            args.local_state or DEFAULT_LOCAL_STATE_PATH
        )
    
    elif args.dpapi_guid and args.password_sha1:
        print("[+] Deriving from DPAPI GUID and password SHA1")
        return derive_chrome_key_from_guid_password(
            args.dpapi_guid,
            args.password_sha1,
            args.local_state or DEFAULT_LOCAL_STATE_PATH
        )
    
    else:
        print("[+] Attempting automatic extraction from Local State")
        try:
            with open(args.local_state or DEFAULT_LOCAL_STATE_PATH, "r", encoding="utf-8") as f:
                local_state = json.loads(f.read())
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            if encrypted_key.startswith(b'DPAPI'):
                encrypted_key = encrypted_key[5:]
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            print("[+] Master key extracted successfully")
            return key
        except Exception as e:
            raise RuntimeError(f"Failed to extract encryption key: {str(e)}")

def is_json(data):
    """Check if data is valid JSON"""
    try:
        json.loads(data)
        return True
    except (ValueError, TypeError):
        return False

def unwrap_json_cookie(cookie_value):
    """Unwrap JSON-formatted cookie values with better handling"""
    if not isinstance(cookie_value, str):
        return cookie_value
    
    # First try to URL decode if needed
    try:
        decoded_value = unquote(cookie_value)
        if decoded_value != cookie_value:
            cookie_value = decoded_value
    except:
        pass
    
    # Check if it's JSON
    if not is_json(cookie_value):
        return cookie_value
    
    try:
        data = json.loads(cookie_value)
        if isinstance(data, dict):
            # Special case for simple dictionaries with one numeric value
            if len(data) == 1 and isinstance(list(data.values())[0], (int, float)):
                return str(list(data.values())[0])
            
            # Common JSON cookie structures
            if 'value' in data:
                return data['value']
            elif 'data' in data:
                return data['data']
            elif all(isinstance(v, (str, int, float, bool)) for v in data.values()) and len(data) <= 3:
                return json.dumps(data)  # Return compact JSON for simple objects
            else:
                return json.dumps(data, indent=2)  # Pretty print for complex objects
        elif isinstance(data, (list, tuple)) and len(data) == 1:
            return str(data[0])
        return str(data)
    except Exception as e:
        return f"[JSON PARSE ERROR: {str(e)}]"

def categorize_cookie(name):
    """Categorize cookies by their type/purpose (simplified to match v1)"""
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
    """Attempt to decode URL-encoded cookie values"""
    try:
        decoded = unquote(value)
        if decoded != value:
            return decoded
    except:
        pass
    return value

def decrypt_value(encrypted_value, key):
    """Decrypt Chrome cookie value"""
    if not encrypted_value:
        return "[EMPTY]"
    try:
        if not encrypted_value.startswith(b'v10') and not encrypted_value.startswith(b'v11'):
            return encrypted_value.decode('utf-8', errors='ignore')
        
        # Remove version prefix
        encrypted_value = encrypted_value[3:]
        # Extract nonce (first 12 bytes) and ciphertext
        nonce = encrypted_value[:12]
        ciphertext = encrypted_value[12:-16]
        tag = encrypted_value[-16:]
        
        # Decrypt using AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        decoded = decrypted.decode('utf-8', errors='ignore')
        return unwrap_json_cookie(decoded)
    except Exception as e:
        return f"[DECRYPT FAILED: {str(e)}]"

def clean_output(host, name, value):
    """Format output to match the desired style with proper JSON handling"""
    host_clean = host if isinstance(host, str) else host.decode('utf-8', errors='replace').strip()
    name_clean = name if isinstance(name, str) else name.decode('utf-8', errors='replace').strip()
    
    if value in ("[EMPTY]", "[NON-ENCRYPTED]"):
        return f"=> {host_clean} | {name_clean} = {value}\n"
    
    # Handle JSON values
    if isinstance(value, str) and is_json(value):
        try:
            json_data = json.loads(value)
            if isinstance(json_data, dict) and len(json_data) == 1 and isinstance(list(json_data.values())[0], (int, float)):
                # Simple numeric JSON like {"value": 3600000}
                return f"=> {host_clean} | {name_clean} = {list(json_data.values())[0]}\n"
            elif isinstance(json_data, (int, float)):
                # Simple numeric value that was in JSON format
                return f"=> {host_clean} | {name_clean} = {json_data}\n"
            else:
                # Complex JSON that needs pretty printing
                json_str = json.dumps(json_data, indent=2)
                return f"=> {host_clean} | {name_clean} = (JSON)\n{json_str}\n"
        except:
            pass
    
    return f"=> {host_clean} | {name_clean} = {value}\n"

def decrypt_cookies(key, cookies_path=None):
    """Main function to decrypt and display cookies (with v1 style output)"""
    if cookies_path is None:
        cookies_path = DEFAULT_COOKIES_PATH
    
    conn = None
    stats = defaultdict(int)
    processed_count = 0
    all_cookies = defaultdict(list)

    try:
        conn = sqlite3.connect(cookies_path)
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
            decrypted = decrypt_value(encrypted_value, key)
            category = categorize_cookie(name.decode('utf-8', errors='replace'))
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
    parser = argparse.ArgumentParser(description='Decrypt Chrome cookies with multiple credential options')
    parser.add_argument('--master-key', help='Direct Chrome master key (32 bytes hex)')
    parser.add_argument('--dpapi-master-key', help='DPAPI master key (64 bytes hex)')
    parser.add_argument('--dpapi-guid', help='DPAPI GUID for key derivation')
    parser.add_argument('--password-sha1', help='SHA1 hash of user password')
    parser.add_argument('--local-state', help='Path to Chrome Local State file')
    parser.add_argument('--cookies', help='Path to Chrome Cookies database')
    
    args = parser.parse_args()

    try:
        print_banner()

        cookies_path = args.cookies or DEFAULT_COOKIES_PATH
        
        if not check_prerequisites(cookies_path):
            print("\n❌ Prerequisites check failed. Please resolve the issues above.")
            input("\nPress Enter to exit...")
            return
        
        print("\n[+] Starting decryption process...")
        time.sleep(1)
        
        chrome_master_key = get_chrome_master_key(args)
        print(f"[+] Chrome Master Key: {chrome_master_key.hex()}")
        print(f"[+] Chrome Master Key Length: {len(chrome_master_key)} bytes")
        print("\n" + "=" * 65)
        print("  IMPORTANT: The following data contains sensitive information")
        print("  Please handle with care and do not share publicly")
        print("=" * 65)
        
        input("\nPress Enter to continue with cookie decryption...")
        decrypt_cookies(chrome_master_key, cookies_path)
        print("\n[!] Cookie decryption completed successfully!")
        print("[+] Tip: You can scroll up to review all the decrypted cookies")
    
    except KeyboardInterrupt:
        print("\n\n[-] Process interrupted by user")
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