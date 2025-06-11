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

# Paths - MODIFY IF USING DIFFERENT PROFILE
USER_PROFILE = os.environ['USERPROFILE']
LOCAL_STATE_PATH = os.path.join(USER_PROFILE, 
                              r'AppData\Local\Google\Chrome\User Data\Local State')
COOKIES_PATH = os.path.join(USER_PROFILE,
                          r'AppData\Local\Google\Chrome\User Data\Default\Network\Cookies')

def print_banner():
    """Display a friendly banner"""
    print("=" * 60)
    print("    🍪 Chrome Cookie Decryption Tool")
    print("=" * 60)
    print("This tool will safely decrypt and display your Chrome cookies.")
    print("All processing is done locally on your machine.\n")

def check_prerequisites():
    """Check if required files exist and Chrome is closed"""
    print("🔍 Checking prerequisites...")
    
    if not os.path.exists(LOCAL_STATE_PATH):
        print("❌ Chrome Local State file not found!")
        print(f"   Expected location: {LOCAL_STATE_PATH}")
        return False
    
    if not os.path.exists(COOKIES_PATH):
        print("❌ Chrome Cookies database not found!")
        print(f"   Expected location: {COOKIES_PATH}")
        return False
    
    print("✅ Chrome files found")
    print("⚠️  Please ensure Chrome is completely closed before continuing")
    return True

def get_master_key():
    """For Chrome 104 - Gets key from Local State without app_bound_encrypted_key"""
    print("🔑 Extracting master encryption key...")
    try:
        with open(LOCAL_STATE_PATH, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        
        if encrypted_key.startswith(b'DPAPI'):
            encrypted_key = encrypted_key[5:]
        
        key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        print("✅ Master key extracted successfully")
        return key
    
    except Exception as e:
        raise RuntimeError(f"Failed to extract encryption key: {str(e)}")

def is_json(value):
    """More accurate JSON detection"""
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
    """
    If the decrypted value is JSON and contains a 'value' field, return it.
    Otherwise, return the original.
    """
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
    """Handle URL decoding and UTF-8 conversion"""
    try:
        decoded = value.decode('utf-8')
        if '%' in decoded:
            return unquote(decoded)
        return decoded
    except UnicodeDecodeError:
        return value.decode('utf-8', errors='replace')

def decrypt_value(encrypted_value, key):
    """Improved decryption with better empty value handling"""
    if not encrypted_value:
        return "[EMPTY]"
    
    # Handle non-encrypted values (like '12345' etc)
    try:
        if not encrypted_value.startswith(b'v10'):
            try:
                return decode_cookie_value(encrypted_value)
            except:
                return "[NON-ENCRYPTED]"
        
        # Proper decryption for v10 encrypted values
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
    """Improved output formatting"""
    host_clean = host.decode().strip()
    name_clean = name.decode().strip()
    category = categorize_cookie(name_clean)
    
    # Skip printing empty values
    if value in ("[EMPTY]", "[NON-ENCRYPTED]"):
        return f"🌐 {host_clean} | {name_clean} = {value}"
    
    # Handle JSON display
    if is_json(value):
        try:
            json_data = json.loads(value)
            json_str = json.dumps(json_data, indent=2)[:200]  # Limit JSON preview
            return f"🌐 {host_clean} | {name_clean} = (JSON)\n{json_str}..."
        except:
            pass
    
    # Regular value display
    value_str = str(value)
    if len(value_str) > 100:
        return f"🌐 {host_clean} | {name_clean} = {value_str[:100]}... ({len(value_str)} chars)"
    
    return f"🌐 {host_clean} | {name_clean} = {value_str}"

def decrypt_cookies(master_key):
    """Decrypts Chrome cookies with improved handling and statistics"""
    print("🔓 Starting cookie decryption process...")
    conn = None
    stats = defaultdict(int)
    processed_count = 0
    
    try:
        conn = sqlite3.connect(COOKIES_PATH)
        conn.text_factory = bytes
        cursor = conn.cursor()
        
        # Get total count for progress indication
        cursor.execute("SELECT COUNT(*) FROM cookies")
        total_cookies = cursor.fetchone()[0]
        
        print(f"📊 Found {total_cookies} cookies to process")
        print("\n" + "=" * 60)
        print("🍪 DECRYPTED COOKIES:")
        print("=" * 60)
        
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        
        for host, name, encrypted_value in cursor.fetchall():
            processed_count += 1
            decrypted = decrypt_value(encrypted_value, master_key)
            category = categorize_cookie(name.decode())
            stats[category] += 1
            
            print(clean_output(host, name, decrypted))
            
            # Show progress for large datasets
            if processed_count % 50 == 0:
                print(f"\n⏳ Progress: {processed_count}/{total_cookies} cookies processed...\n")
        
        # Print summary
        print("\n" + "=" * 60)
        print("📈 SUMMARY STATISTICS:")
        print("=" * 60)
        for cat, count in sorted(stats.items()):
            emoji = get_category_emoji(cat)
            print(f"  {emoji} {cat}: {count}")
        print(f"  🏆 TOTAL PROCESSED: {sum(stats.values())}")
        print("=" * 60)
    
    except Exception as e:
        print(f"❌ Database error: {str(e)}")
        print("💡 Make sure Chrome is completely closed and try again")
    finally:
        if conn:
            conn.close()

def get_category_emoji(category):
    """Return appropriate emoji for each category"""
    emoji_map = {
        'AUTH': '🔐',
        'SESSION': '⏱️',
        'TOKEN': '🎟️',
        'IDENTIFIER': '🆔',
        'CONSENT': '✅',
        'OTHER': '📄'
    }
    return emoji_map.get(category, '📄')

def main():
    """Main execution function with improved user experience"""
    try:
        print_banner()
        
        if not check_prerequisites():
            print("\n❌ Prerequisites check failed. Please resolve the issues above.")
            input("\nPress Enter to exit...")
            return
        
        print("\n⏳ Starting decryption process...")
        time.sleep(1)  # Brief pause for better UX
        
        master_key = get_master_key()
        print(f"🔑 Master Key Length: {len(master_key)} bytes")
        
        print("\n" + "⚠️ " * 20)
        print("  IMPORTANT: The following data contains sensitive information")
        print("  Please handle with care and do not share publicly")
        print("⚠️ " * 20)
        
        input("\nPress Enter to continue with cookie decryption...")
        
        decrypt_cookies(master_key)
        
        print("\n✅ Cookie decryption completed successfully!")
        print("💡 Tip: You can scroll up to review all the decrypted cookies")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Process interrupted by user")
    except Exception as e:
        print(f"\n❌ Critical Error: {str(e)}")
        print("💡 Common solutions:")
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