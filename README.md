# 🛡️ Chrome Decryptor (v2 - Offline Mode)

**Chrome Decryptor v2** is a powerful offline tool for decrypting Google Chrome cookies. This enhanced version allows direct decryption **without relying on a running Chrome instance** by accepting the Chrome master key in multiple ways.

It was built for forensic investigations, red teaming, and advanced offline analysis of Chrome user profiles.

---

## 🔍 Features

- 🔓 Decrypts AES-GCM encrypted Chrome cookies (v10 and v11)
- 📂 Works completely **offline** using:
  - Chrome Master Key (`--master-key`)
  - DPAPI Master Key (`--dpapi-master-key`)
  - DPAPI GUID + Password SHA1 (`--dpapi-guid + --password-sha1`)
  - Automatic extraction (if running locally)
- 📦 Categorizes cookies:
  - Session tokens
  - Authentication tokens
  - JWTs
  - Identifiers
  - Consent flags
- 🧩 Allows JSON unwrapping and smart formatting
- 🗃️ Shows statistics per cookie category
- 👁️ Interactive mode for exploring decrypted cookies by type

---

## 🚀 Usage

### Minimal

```bash
python chrome_decryptor_final.py --master-key YOUR_CHROME_MASTER_KEY_HEX
```

> You can extract the master key from the Chrome Local State file manually or derive it using DPAPI methods.

### Full Options

```bash
python chrome_decryptor_final.py 
    [--master-key HEX] 
    [--dpapi-master-key HEX] 
    [--dpapi-guid GUID --password-sha1 HASH] 
    [--local-state PATH] 
    [--cookies PATH]
```

- `--master-key`: Direct 32-byte hex master key
- `--dpapi-master-key`: Windows DPAPI master key (used to decrypt Chrome’s key)
- `--dpapi-guid + --password-sha1`: Derive key with known credentials
- `--local-state`: Path to the Local State JSON (default is system path)
- `--cookies`: Path to `Cookies` SQLite DB (default is system path)

---

## 📦 Example Output

```
=> www.site.com | session_id = abc123xyz...
=> auth.example.com | jwt_token = (JSON)
{
  "value": "eyJhbGciOiJIUzI1NiIsInR..."
}
```

---

## 📂 Requirements

- Windows system
- Python 3.8+
- Encrypted `Cookies` SQLite file
- `Local State` file (if deriving key)
- One of the following:
  - Chrome Master Key
  - DPAPI Master Key
  - DPAPI GUID + Password Hash

---

## ⚙️ Dependencies

Save this as `requirements.txt`:

```txt
pycryptodome
pywin32
dpapick3
```

Install via:

```bash
pip install -r requirements.txt
```

---

## ⚠️ Disclaimer

This tool is intended **strictly for ethical, educational, or forensic purposes** only.  
Do not use this software on systems you do not own or have explicit permission to analyze.

---

## 🙋‍♂️ Author

**Theodoros**  
Junior Penetration Tester | Cybersecurity Intern  
