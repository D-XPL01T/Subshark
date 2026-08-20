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

# Import the banner module from the same directory
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
    # FIXED: Changed "domjack" to "subshark"
    return str(Path.home() / ".config" / "subshark" / "fingerprints.json")

def ensure_config_directory(verbose):
    # FIXED: Changed "domjack" to "subshark"
    config_dir = Path.home() / ".config" / "subshark"
    config_dir.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"[*] Config directory: {config_dir}", file=sys.stderr)

def download_fingerprints(url, dest_path, verbose):
    if verbose:
        print(f"[*] Downloading fingerprints.json from {url}", file=sys.stderr)
    
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read()
    except Exception as e:
        raise Exception(f"failed to download fingerprints: {e}")
        
    try:
        json.loads(body)
    except Exception as e:
        raise Exception(f"downloaded file is not valid JSON: {e}")
        
    with open(dest_path, 'wb') as f:
        f.write(body)
        
    if verbose:
        print(f"[*] Saved fingerprints.json to {dest_path}", file=sys.stderr)

def get_fingerprints_path(custom_path, verbose):
    if custom_path:
        return custom_path
        
    default_path = get_default_fingerprints_path()
    if not os.path.exists(default_path):
        ensure_config_directory(verbose)
        github_url = "https://raw.githubusercontent.com/D-XPL01T/Subshark/refs/heads/main/fingerprints.json"
        download_fingerprints(github_url, default_path, verbose)
        
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
    # FIXED: Updated description to SubShark
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
        # FIXED: Added 'banner.' prefix
        banner.print_banner()
        banner.print_version()
        return
        
    if not args.silent:
        # FIXED: Added 'banner.' prefix
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
        # FIXED: Proper newline escape
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
            # FIXED: Proper newline escape
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
            return
        try:
            body, working_url = fetch_url_with_fallback(url, args.timeout, args.user_agent)
        except Exception:
            done_queue.put(index)
            return
            
        for fp in fingerprints:
            matched, is_match = check_fingerprint(fp, body)
            if is_match:
                with vuln_count_lock:
                    vuln_count += 1
                result = {
                    "service": fp.get('service'),
                    "severity": fp.get('severity'),
                    "url": working_url,
                    "fingerprint": matched
                }
                if args.json or args.output:
                    result_queue.put(result)
                if not args.json:
                    format_output(fp.get('service'), fp.get('severity'), working_url, matched, args.nc)
                    
        done_queue.put(index)

    prog_thread = threading.Thread(target=progress_collector)
    prog_thread.start()
    
    collector_thread = None
    if args.json or args.output:
        collector_thread = threading.Thread(target=result_collector)
        collector_thread.start()
        
    total = len(urls)
    if not args.no_resume and start >= total:
        if not args.silent:
            print("[!] Nothing to do; all items already scanned. Use --no-resume to start over.", file=sys.stderr)
        delete_resume(resume_path)
        return

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = []
        for idx in range(start, total):
            if cancel_event.is_set():
                break
            futures.append(executor.submit(process_url, idx, urls[idx]))
            
        for f in futures:
            try:
                f.result()
            except Exception:
                pass
            
    done_queue.put(None)
    prog_thread.join()
    
    if next_local >= total and not interrupted:
        delete_resume(resume_path)
        
    if interrupted:
        print("[*] Progress saved to resume.cfg. Re-run the same command to resume, or use --no-resume to start over.", file=sys.stderr)
        
    if args.json or args.output:
        result_queue.put(None)
        if collector_thread:
            collector_thread.join()
            
        if args.json:
            with results_mutex:
                print(json.dumps(results_list, indent=2))
                
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                with results_mutex:
                    for res in unique_results.values():
                        fp_str = ", ".join(res['fingerprint'])
                        # FIXED: Proper newline escape
                        line = f"[{res['service']}] [{res['severity']}] {res['url']} [{fp_str}]\n"
                        f.write(line)
            if args.verbose:
                print(f"[*] Saved {len(unique_results)} unique results to {args.output}", file=sys.stderr)
    
    # Print summary
    scanned_count = next_local if next_local <= total else total
    if vuln_count > 0:
        # FIXED: Proper newline escape
        print(f"\n{COLOR_BRIGHT_GREEN}[✓] Scan complete: {scanned_count} URL(s) scanned, {vuln_count} potential subdomain hijacking vulnerability(ies) found!{COLOR_RESET}")
    else:
        # FIXED: Proper newline escape
        print(f"\n{COLOR_YELLOW}[-] Scan complete: {scanned_count} URL(s) scanned, no vulnerabilities found.{COLOR_RESET}")

if __name__ == "__main__":
    main()