import os
import re
import sys

SUSPICIOUS_PATTERNS = {
    "sensitive_info": [
        r"password", r"secret", r"api_key", r"access_key", r"token", 
        r"credentials", r"auth_header", r"\.env", r"\.ssh", r"\.aws", 
        r"id_rsa", r"private_key"
    ],
    "download_malware": [
        r"curl", r"wget", r"requests\.get", r"urllib", r"http\.client", 
        r"download", r"fetch", r"axios", r"invoke-webrequest"
    ],
    "execute_scripts": [
        r"os\.system", r"subprocess\.call", r"subprocess\.Popen", r"exec\(", 
        r"eval\(", r"sh -c", r"cmd\.exe", r"powershell", r"child_process", 
        r"spawn"
    ],
    "full_disk_scan": [
        r"os\.walk\(['\"]/['\"]", r"os\.walk\(['\"]~['\"]", r"glob\.glob\(['\"]/\*\*", 
        r"glob\.glob\(['\"]~/\*\*", r"find / ", r"ls -R /"
    ],
    "delete_files": [
        r"rm -rf", r"os\.remove", r"os\.unlink", r"shutil\.rmtree", 
        r"fs\.unlink", r"fs\.rmdir", r"del /s /q"
    ],
    "obfuscation": [
        r"base64\.b64decode", r"codecs\.decode", r"eval\(base64"
    ]
}

def scan_file(filepath):
    issues = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                for category, patterns in SUSPICIOUS_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            issues.append({
                                "file": filepath,
                                "line": i + 1,
                                "category": category,
                                "pattern": pattern,
                                "content": line.strip()
                            })
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return issues

def scan_directory(directory):
    all_issues = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.js', '.sh', '.md', '.txt', '.json')):
                filepath = os.path.join(root, file)
                issues = scan_file(filepath)
                all_issues.extend(issues)
    return all_issues

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python audit_check.py <directory_to_scan>")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    if not os.path.exists(target_dir):
        print(f"Directory not found: {target_dir}")
        sys.exit(1)
        
    print(f"Scanning directory: {target_dir}")
    issues = scan_directory(target_dir)
    
    if issues:
        print(f"Found {len(issues)} potential issues:")
        for issue in issues:
            print(f"[{issue['category'].upper()}] {issue['file']}:{issue['line']}")
            print(f"  Pattern: {issue['pattern']}")
            print(f"  Content: {issue['content']}")
            print("-" * 40)
    else:
        print("No suspicious patterns found.")
