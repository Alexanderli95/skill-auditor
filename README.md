# Skill Auditor

A security auditing skill for Trae that scans codebases (specifically other skills or plugins) for potentially malicious patterns and security risks.

## 📋 Overview

Skill Auditor is designed to help developers and users verify the safety of third-party skills or scripts before using them. It performs a static analysis scan to detect common malicious behaviors such as sensitive information leakage, malware downloads, unauthorized execution, and file system tampering.

## ✨ Features

- **Sensitive Information Detection**: Scans for hardcoded secrets, API keys, tokens, and access to sensitive files (e.g., `.env`, `.ssh`).
- **Malware Download Detection**: Identifies network requests and download commands (e.g., `curl`, `wget`, `requests.get`) that could fetch malicious payloads.
- **Execution Monitoring**: Flags dangerous execution patterns like `eval()`, `exec()`, `os.system()`, and shell command injections.
- **Full Disk Scan Alert**: Detects attempts to recursively scan the entire file system (e.g., `/` or `~`).
- **File Deletion Warning**: Warns about destructive file operations (e.g., `rm -rf`, `shutil.rmtree`).
- **Obfuscation Detection**: Checks for base64 decoding and other common obfuscation techniques used to hide malicious code.
- **Prompt Auditing**: Dumps markdown documentation to allow LLM-based analysis of malicious instructions (e.g., phishing, data exfiltration).

## 🚀 Installation

This skill is intended to be used within the Trae environment. Ensure the `skill-auditor` directory is placed within your `.trae/skills/` directory.

```
.trae/skills/skill-auditor/
├── README.md
├── SKILL.md
└── scripts/
    └── audit_check.py
```

## 📖 Usage

### Triggering the Skill

You can invoke this skill in your Trae chat by asking:
- "Audit this directory for security risks"
- "Check if this skill has malicious code"
- "Scan [path/to/skill] for viruses"

### Manual Execution

The core logic is contained in a Python script that can also be run standalone: 

```bash
python scripts/audit_check.py <path_to_target_directory> [--read-md]
```

Use `--read-md` to dump the content of all markdown files for manual or LLM review.

### Example Output

```text
Scanning directory: /path/to/suspicious-skill
Found 2 potential issues:
[DELETE_FILES] /path/to/suspicious-skill/cleanup.py:15
  Pattern: rm -rf
  Content: os.system("rm -rf /")
----------------------------------------
[SENSITIVE_INFO] /path/to/suspicious-skill/config.js:3
  Pattern: api_key
  Content: const api_key = "sk-12345abcdef"
----------------------------------------
```

## 🔍 Detection Patterns

The auditor scans for regex patterns across the following categories:

| Category | Description | Examples |
|----------|-------------|----------|
| `sensitive_info` | Potential leakage of secrets | `password`, `api_key`, `.env`, `id_rsa` |
| `download_malware` | Downloading external content | `curl`, `wget`, `requests.get`, `fetch` |
| `execute_scripts` | Arbitrary code execution | `eval()`, `exec()`, `subprocess`, `cmd.exe` |
| `full_disk_scan` | excessive file system access | `os.walk('/')`, `find /`, `glob.glob('/**')` |
| `delete_files` | Destructive file operations | `rm -rf`, `os.remove`, `shutil.rmtree` |
| `obfuscation` | Hidden code payloads | `base64.b64decode`, `eval(base64...)` |

## 🤝 Contributing

Contributions are welcome! If you find new malicious patterns or want to improve the detection logic:

1.  Fork the repository (if applicable) or edit the local files.
2.  Update `scripts/audit_check.py` to add new regex patterns to `SUSPICIOUS_PATTERNS`.
3.  Test the changes against known safe and unsafe code.

## 📄 License

This project is created for the Trae environment. Please refer to the project's main license for usage terms.
