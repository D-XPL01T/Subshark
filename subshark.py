#!/usr/bin/env python3
"""
subshark.py - A fast and efficient subdomain hijacking scanner.
"""
import sys
import os
import json
import argparse
import threading
import queue
import signal
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import banner

# ==========================================
# ANSI Colors
# ==========================================
COLOR_RESET = "\033[0m"
COLOR_BRIGHT_GREEN = "\033[92m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_BRIGHT_CYAN = "\033[96m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"

# ==========================================
# Resume Helpers
# ==========================================
def load_resume(path):
    if not os.path.exists(path):
        return 0
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("scanned="):
                    val = line[len("scanned="):].strip()
                    try:
                        return int(val)
                    except ValueError:
                        pass
    except Exception:
        pass
    return 0

def save_resume(path, scanned):
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(f"scanned={scanned}\n")
    if os.path.exists(path):
        os.remove(path)
    os.rename(tmp, path)

def delete_resume(path):
    if os.path.exists(path):
        os.remove(path)

# ==========================================
# Configuration & Fingerprints
# ==========================================
def get_default_fingerprints_path():
    return str(Path.home() / ".config" / "subshark" / "fingerprints.json")

def ensure_config_directory(verbose):
    config_dir = Path.home() / ".config" / "subshark"
    config_dir.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"[*] Config directory: {config_dir}", file=sys.stderr)

def get_fingerprints_path(custom_path, verbose):
    if custom_path:
        return custom_path
        
    default_path = get_default_fingerprints_path()
    if not os.path.exists(default_path):
        ensure_config_directory(verbose)
        print(f"[!] Fingerprints file not found at: {default_path}", file=sys.stderr)
        print("[!] Please provide a valid fingerprints.json using the --fingerprints flag,", file=sys.stderr)
        print("[!] or place it in the default directory mentioned above.", file=sys.stderr)
        sys.exit(1)
        
    return default_path

def load_fingerprints(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        data = f.read()
    try:
        return json.loads(data)
    except Exception as e:
        raise Exception(f"failed to parse fingerprints JSON: {e}")

def parse_service_list(service_list):
    result = set()
    if not service_list:
        return result
    for s in service_list.split(","):
        s = s.strip()
        if s:
            result.add(s)
    return result

def filter_fingerprints(all_fps, exclude_str, onlycheck_str, verbose):
    filtered = []
    if exclude_str:
        exclude_services = parse_service_list(exclude_str)
        for fp in all_fps:
            if fp.get('service') not in exclude_services:
                filtered.append(fp)
        if verbose:
            print(f"[*] Excluded services: {', '.join(exclude_services)}", file=sys.stderr)
    elif onlycheck_str:
        onlycheck_services = parse_service_list(onlycheck_str)
        for fp in all_fps:
            if fp.get('service') in onlycheck_services:
                filtered.append(fp)
        if verbose:
            print(f"[*] Only checking services: {', '.join(onlycheck_services)}", file=sys.stderr)
    else:
        filtered = all_fps
    return filtered

# ==========================================
# HTTP & Fingerprint Logic
# ==========================================
def normalize_url(url):
    url = url.strip()
    if not url:
        return ""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return url

def fetch_url(url, timeout, user_agent):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        raise Exception(f"failed to fetch URL: {e}")

def fetch_url_with_fallback(domain, timeout, user_agent):
    if domain.startswith("http://") or domain.startswith("https://"):
        body = fetch_url(domain, timeout, user_agent)
        return body, domain
        
    https_url = "https://" + domain
    try:
        body = fetch_url(https_url, timeout, user_agent)
        return body, https_url
    except Exception:
        pass
        
    http_url = "http://" + domain
    body = fetch_url(http_url, timeout, user_agent)
    return body, http_url

def check_fingerprint(fp, response_body):
    matched = []
    condition = fp.get('matchcondition', 'ANY')
    patterns = fp.get('fingerprint', [])
    
    if condition == "ANY":
        for pattern in patterns:
            if pattern in response_body:
                matched.append(pattern)
        return matched, len(matched) > 0
    elif condition == "ALL":
        for pattern in patterns:
            if pattern in response_body:
                matched.append(pattern)
        return matched, len(matched) == len(patterns)
        
    return [], False

def format_output(service, severity, url, matched_fingerprints, no_color):
    if not matched_fingerprints:
        return
    fp_str = ", ".join(matched_fingerprints)
    if no_color:
        print(f"[{service}] [{severity}] {url} [{fp_str}]")
    else:
        print(f"[{COLOR_BRIGHT_GREEN}{service}{COLOR_RESET}] [{COLOR_ORANGE}{severity}{COLOR_RESET}] {url} [{COLOR_BRIGHT_CYAN}{fp_str}{COLOR_RESET}]")

# ==========================================
# Main Execution
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="SubShark - Fast Subdomain Hijacking Scanner")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds for HTTP requests")
    parser.add_argument("-H", "--User-Agent", dest="user_agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", help="Custom User-Agent header")
    parser.add_argument("--concurrency", type=int, default=50, help="Number of concurrent subdomains check")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--output", default="", help="Save unique output results to a file")
    parser.add_argument("--fingerprints", default="", help="Custom path to fingerprints.json file")
    parser.add_argument("--es", default="", help="Exclude services (case-sensitive, comma-separated)")
    parser.add_argument("--onlycheck", default="", help="Only check specific services (case-sensitive, comma-separated)")
    parser.add_argument("--nc", action="store_true", help="Disable colored output")
    parser.add_argument("--silent", action="store_true", help="Silent mode")
    parser.add_argument("--version", action="store_true", help="Print the version of the tool and exit")
    parser.add_argument("--verbose", action="store_true", help="Show verbose information")
    parser.add_argument("--no-resume", action="store_true", help="Disable resume functionality and start scanning fresh")
    
    args = parser.parse_args()
    
    if args.version:
        banner.print_banner()
        banner.print_version()
        return
        
    if not args.silent:
        banner.print_banner()
        
    if args.es and args.onlycheck:
        print("Error: --es and --onlycheck cannot be used together", file=sys.stderr)
        sys.exit(1)
        
    try:
        fp_path = get_fingerprints_path(args.fingerprints, args.verbose)
        all_fingerprints = load_fingerprints(fp_path)
    except Exception as e:
        print(f"Error determining/loading fingerprints path: {e}", file=sys.stderr)
        sys.exit(1)
        
    fingerprints = filter_fingerprints(all_fingerprints, args.es, args.onlycheck, args.verbose)
    if not fingerprints:
        print("Error: No fingerprints to check after filtering", file=sys.stderr)
        sys.exit(1)
        
    urls = []
    try:
        for line in sys.stdin:
            url = normalize_url(line)
            if url:
                urls.append(url)
    except KeyboardInterrupt:
        print("\nInterrupted while reading input.", file=sys.stderr)
        sys.exit(0)
            
    if not urls:
        print("[!] No URLs provided. Please provide URLs via stdin.", file=sys.stderr)
        sys.exit(1)
        
    cwd = os.getcwd()
    resume_path = os.path.join(cwd, "resume.cfg")
    start = 0
    
    if args.no_resume:
        delete_resume(resume_path)
        if not args.silent:
            print("[*] Starting fresh; resume disabled (--no-resume)", file=sys.stderr)
    else:
        s = load_resume(resume_path)
        start = s
        if start > 0 and not args.silent:
            print(f"[*] Resuming from scanned={start} (skipping {start} items)", file=sys.stderr)
            
    cancel_event = threading.Event()
    interrupted = False
    
    def signal_handler(sig, frame):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            print("\n[*] Interrupt received. Cancelling pending tasks and saving progress...", file=sys.stderr)
            cancel_event.set()
            
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if not args.no_resume:
        save_resume(resume_path, start)
        
    done_queue = queue.Queue()
    result_queue = queue.Queue()
    results_mutex = threading.Lock()
    unique_results = {}
    results_list = []
    vuln_count = 0
    vuln_count_lock = threading.Lock()
    
    pending_lock = threading.Lock()
    pending = set()
    next_local = start
    
    def progress_collector():
        nonlocal next_local
        while True:
            idx = done_queue.get()
            if idx is None:
                break
            with pending_lock:
                pending.add(idx)
                while next_local in pending:
                    pending.remove(next_local)
                    next_local += 1
                    save_resume(resume_path, next_local)

    def result_collector():
        while True:
            result = result_queue.get()
            if result is None:
                break
            with results_mutex:
                key = f"{result['url']}|{result['service']}"
                if key not in unique_results:
                    unique_results[key] = result
                    if args.json:
                        results_list.append(result)

    def process_url(index, url):
        nonlocal vuln_count
        if cancel_event.is_set():
           