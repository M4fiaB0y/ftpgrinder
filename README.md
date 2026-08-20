# FTP Credential Grinder

**Advanced FTP credential checker & combo cleaner** – a multi‑threaded tool with a rich console UI, built for security research and penetration testing.

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚠️ Disclaimer

**This tool is intended for educational and authorised security testing only.**  
The author is not responsible for any misuse or illegal activity. By using this software, you agree that you will not use it for any malicious purposes and that you have the proper authorisation to test the target systems.

---

## 🚀 Features

- **Combo Cleaner**
  - Parses `host|username|password` lines from a text file
  - Extracts host & port (optional), strips URLs / protocols
  - Blacklists known high‑profile domains (social media, banks, cloud providers, etc.)
  - Performs a quick reachability check (TCP connect) to filter unreachable hosts
  - Removes duplicates automatically
  - Saves **cleaned** combos and **skipped** entries with reason codes

- **FTP Credential Checker**
  - Multi‑threaded (configurable thread count)
  - Tests each combo via `ftplib` with a timeout
  - Real‑time progress bar and live valid‑combo display
  - Writes all valid credentials to `validftp.txt`

- **Rich Console UI**
  - Coloured panels, tables, progress bars, and spinners
  - Auto‑installs `rich` and `tqdm` if missing
  - Logs every check to `ftp_tool.log`

---

## 📦 Requirements

- **Python 3.6+** (or any version that supports `concurrent.futures`)
- Built‑in modules: `ftplib`, `socket`, `re`, `logging`, `datetime`, `os`, `sys`
- Optional third‑party modules (auto‑installed on first run):
  - [`rich`](https://github.com/Textualize/rich) – for beautiful terminal output
  - [`tqdm`](https://github.com/tqdm/tqdm) – for progress bars (used as fallback)

---

## 📥 Installation

```bash
git clone https://github.com/yourusername/ftpgrinder.git
cd ftpgrinder
```

# 🔧 Usage

Run the tool with:

    python ftpgrinder.py

You will be presented with a main menu containing three options.

## 1. Clean & Deduplicate Combo File

- Provide the path to your raw combo file.
- The file should contain one combo per line in the format:
  `host[:port]|username|password`

### Examples

    192.168.1.1|admin|12345
    ftp.example.com:2121|user|pass
    https://example.com|test|test

The cleaner will:

- Strip protocols and URL fragments
- Extract host and port (defaults to 21)
- Blacklist domains (see `BLACKLISTED_DOMAINS` in the code)
- Skip unreachable hosts

### Output Files

- `*_cleaned.txt` — Deduplicated, validated combos
- `*_skipped.txt` — Lines that were skipped, prefixed with a reason code

## 2. Check FTP Credentials

- Provide the path to a **cleaned** combo file.
- Enter the desired number of threads (`1–50`).
- The tool will test each combo and print valid ones in real time.
- Valid credentials are saved to `validftp.txt` in the same `host|user|password` format.

## 3. Exit

Closes the session.

Logs are stored in `ftp_tool.log`.

## 📁 File Formats

| File | Description |
|---|---|
| **Input combo file** | `host[:port]\|username\|password` — one per line |
| **Cleaned output** | Deduplicated, reachable combos |
| **Skipped file** | `reason\toriginal_line` — allows you to review why entries were excluded |
| **Valid FTP file** | `validftp.txt` — all working credentials |
| **Log file** | `ftp_tool.log` — timestamped log of every check and validation |

## 🧠 Skip Reasons

| Reason | Meaning |
|---|---|
| `empty` | Blank line |
| `not_enough_parts` | Missing `\|` separators |
| `empty_host` | Host part is empty |
| `bad_host_format` | Could not parse host / port |
| `blacklisted_domain` | Domain is in the blacklist |
| `host_unreachable` | TCP connection to the host failed |

## ⚙️ Configuration

You can tweak the following constants at the top of `ftp_Checker.py`:

    DEFAULT_PORT    = 21
    DEFAULT_TIMEOUT = 5
    MAX_THREADS     = 50
    BLACKLISTED_DOMAINS = {...}

## 🛡️ Security & Ethics

- **Only test systems you own or have explicit permission to test.**
- This tool does not exploit or crack — it performs standard FTP login attempts.
- The blacklist helps avoid accidentally testing well-known public services.
- All checks are performed with a timeout to prevent hanging.

## 📜 License

This project is licensed under the MIT License.

See the `LICENSE` file for details.

## 🤝 Contributing

Pull requests and suggestions are welcome. Please keep the code clean and maintain the educational intent.

## 📬 Contact

For questions or feedback, please open an issue on GitHub.

---

**Happy (ethical) hacking!** 🔐
