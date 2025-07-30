import argparse
import requests
import socket
import ssl
from colorama import Fore, init, Style
from urllib.parse import urlparse, urljoin, quote
import chardet
import concurrent.futures
import datetime
import os
import sys
import warnings
import platform
import signal
import time
from http.client import responses as http_responses

warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Global flag for interruption
stop_flag = False

def signal_handler(sig, frame):
    global stop_flag
    if not stop_flag:
        print(Fore.RED + "\n[!] Received interrupt signal. Stopping gracefully...")
        stop_flag = True
        sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def load_wordlist(wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(Fore.RED + f"\n[!] Error: Wordlist file not found: {wordlist_path}")
        sys.exit(1)
        
    try:
        # First try to detect encoding
        with open(wordlist_path, 'rb') as f:
            raw = f.read(1024 * 1024)  # Read first 1MB for encoding detection
            result = chardet.detect(raw)
            encoding = result['encoding'] or 'utf-8'
            confidence = result.get('confidence', 0)
            
            if confidence < 0.7:  # If confidence is low, try common encodings
                for enc in ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']:
                    try:
                        raw.decode(enc)
                        encoding = enc
                        break
                    except UnicodeDecodeError:
                        continue
        
        # Read the file with detected encoding
        with open(wordlist_path, 'r', encoding=encoding, errors='ignore') as f:
            # Remove empty lines and duplicates, preserve order
            seen = set()
            return [x for x in (line.strip() for line in f) 
                   if x and not (x in seen or seen.add(x))]
    
    except (IOError, OSError) as e:
        print(Fore.RED + f"\n[!] I/O Error reading wordlist: {e}")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error reading wordlist: {e}")
        sys.exit(1)

def check_path(base_url, path, headers, log_file, timeout, verify_ssl, follow_redirects):
    global stop_flag
    if stop_flag:
        return
    
    try:
        # URL encode the path to handle special characters
        encoded_path = quote(path, safe="/#%[]=:;$&()+,!?*@'~")
        full_url = urljoin(base_url, encoded_path)
        
        # Add a small delay to avoid overwhelming the server
        time.sleep(0.1)
        
        try:
            response = requests.get(
                full_url,
                headers=headers,
                allow_redirects=follow_redirects,
                timeout=timeout,
                verify=verify_ssl,
                stream=True  # Stream the response to handle large files efficiently
            )
            
            if stop_flag:
                return
                
            # Get response size efficiently
            size = int(response.headers.get('content-length', 0))
            if not size:  # If content-length not provided, read response
                size = len(response.content)
                
            status = response.status_code
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Get response time
            response_time = response.elapsed.total_seconds() * 1000  # in milliseconds
            
            # Get response headers for additional information
            server = response.headers.get('Server', 'Unknown')
            content_type = response.headers.get('Content-Type', 'Unknown').split(';')[0]
            
            log_entry = (
                f"[{timestamp}] {status} "
                f"({size} bytes, {response_time:.2f}ms, {server}, {content_type}) -> {full_url}\n"
            )
            
            # Extended status code handling
            status_codes = {
                # Success
                200: (Fore.GREEN, "[+] 200 OK"),
                201: (Fore.CYAN, "[i] 201 Created"),
                202: (Fore.CYAN, "[i] 202 Accepted"),
                204: (Fore.CYAN, "[i] 204 No Content"),
                # Redirection
                301: (Fore.YELLOW, "[→] 301 Moved Permanently"),
                302: (Fore.YELLOW, "[→] 302 Found"),
                303: (Fore.YELLOW, "[→] 303 See Other"),
                307: (Fore.YELLOW, "[→] 307 Temporary Redirect"),
                308: (Fore.YELLOW, "[→] 308 Permanent Redirect"),
                # Client Errors
                400: (Fore.RED, "[!] 400 Bad Request"),
                401: (Fore.BLUE, "[!] 401 Unauthorized"),
                402: (Fore.BLUE, "[!] 402 Payment Required"),
                403: (Fore.MAGENTA, "[!] 403 Forbidden"),
                404: (None, ""),  # Hidden by default
                405: (Fore.RED, "[!] 405 Method Not Allowed"),
                406: (Fore.RED, "[!] 406 Not Acceptable"),
                407: (Fore.BLUE, "[!] 407 Proxy Auth Required"),
                408: (Fore.RED, "[!] 408 Request Timeout"),
                409: (Fore.RED, "[!] 409 Conflict"),
                410: (Fore.RED, "[!] 410 Gone"),
                # Server Errors
                500: (Fore.RED, "[☠] 500 Internal Server Error"),
                501: (Fore.RED, "[☠] 501 Not Implemented"),
                502: (Fore.RED, "[☠] 502 Bad Gateway"),
                503: (Fore.RED, "[☠] 503 Service Unavailable"),
                504: (Fore.RED, "[☠] 504 Gateway Timeout"),
                505: (Fore.RED, "[☠] 505 HTTP Version Not Supported")
            }
            
            # Get status message or default to standard message
            status_info = status_codes.get(status, (None, None))
            
            # Only show interesting responses (not 404s, or 404s with content)
            if status_info[0] is not None and (status != 404 or size > 0):
                color, message = status_info
                status_text = http_responses.get(status, 'Unknown Status')
                print(f"{color}{message} ({size} bytes, {response_time:.2f}ms): {full_url}")
                print(f"{Style.DIM}   Server: {server}, Content-Type: {content_type}, Status: {status} {status_text}{Style.RESET_ALL}")
        
        except requests.exceptions.SSLError as e:
            if not stop_flag:
                print(Fore.RED + f"[!] SSL Error: {full_url} - {str(e)}")
            return
            
        except requests.exceptions.Timeout:
            if not stop_flag:
                print(Fore.YELLOW + f"[!] Timeout: {full_url}")
            return
            
        except requests.exceptions.TooManyRedirects:
            if not stop_flag:
                print(Fore.YELLOW + f"[!] Too many redirects: {full_url}")
            return
            
        except requests.exceptions.RequestException as e:
            if not stop_flag:
                print(Fore.RED + f"[!] Request failed: {full_url} - {str(e)}")
            return
            
        # Log to file if specified and not a 404
        if log_file and status != 404 and not stop_flag:
            try:
                with open(log_file, 'a', encoding='utf-8') as log:
                    log.write(log_entry)
            except IOError as e:
                print(Fore.RED + f"[!] Failed to write to log file: {e}")
                
    except Exception as e:
        if not stop_flag:
            error_type = type(e).__name__
            print(Fore.RED + f"[!] Error ({error_type}): {full_url if 'full_url' in locals() else 'Unknown URL'} - {str(e)}")

def validate_url(url):
    """Validate and normalize the target URL."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)
            
        if not parsed.netloc:
            raise ValueError("Invalid URL: No hostname provided")
            
        # Normalize the URL
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Rebuild URL with normalized components
        normalized = f"{scheme}://{netloc}"
        if parsed.path:
            normalized += parsed.path
            
        # Ensure URL ends with a slash if it's just the domain
        if not parsed.path or parsed.path == '/':
            normalized = normalized.rstrip('/') + '/'
            
        return normalized
    except Exception as e:
        print(Fore.RED + f"[!] Invalid URL: {e}")
        sys.exit(1)

def get_user_agent():
    """Return a random user agent string."""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    ]
    import random
    return random.choice(user_agents)

def main():
    global stop_flag
    
    # Print banner
    print(Fore.GREEN + r"""
      ___              ____                              __                     
   F __".   _ ___   F ___J  _    _    _____    _____   LJ   _ ___      ___ _  
  J |--\ L J '__ ",J |___: J |  | L  [__   F  [__   F      J '__ J    F __` L 
  | |  J | | |__|-J| _____|| |  | |  `-.'.'/  `-.'.'/  FJ  | |__| |  | |--| | 
  F L__J | F L  `-'F |____JF L__J J  .' (_(_  .' (_(_ J  L F L  J J  F L__J J 
 J______/FJ__L    J__F    J\____,__LJ_______LJ_______LJ__LJ__L  J__L )-____  L
 |______F |__L    |__|     J____,__F|_______||_______||__||__L  J__|J\______/F
                                                                     J______F         
""")

    print(Fore.CYAN + "=" * 80)
    print(f"{Fore.YELLOW}drfuzzing - Advanced Web Path Fuzzer")
    print(f"{Fore.CYAN}Created by: hancock")
    print(f"{Fore.WHITE}Version: 2.0")
    print(Fore.CYAN + "=" * 80 + "\n")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Advanced Web Path Fuzzer")
    
    # Required arguments
    parser.add_argument("-u", "--url", required=True, 
                       help="Target URL (e.g., http://example.com or example.com)")
    parser.add_argument("-w", "--wordlist", required=True, 
                       help="Path to wordlist file")
    
    # Optional arguments
    parser.add_argument("-t", "--threads", type=int, default=10, 
                       help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", 
                       help="Output file to save results")
    parser.add_argument("--timeout", type=int, default=15,
                       help="Request timeout in seconds (default: 15)")
    parser.add_argument("--no-ssl-verify", action="store_false", 
                       help="Disable SSL certificate verification")
    parser.add_argument("--no-redirects", action="store_false", 
                       help="Disable following redirects")
    parser.add_argument("--show-all", action="store_true",
                       help="Show all responses including 404s")
    parser.add_argument("--delay", type=float, default=0.1,
                       help="Delay between requests in seconds (default: 0.1)")
    
    args = parser.parse_args()
    
    # Validate and normalize the URL
    base_url = validate_url(args.url.strip())
    
    # Load wordlist
    try:
        print(Fore.WHITE + "[~] Loading wordlist...")
        paths = load_wordlist(args.wordlist)
        if not paths:
            print(Fore.RED + "[!] Error: Wordlist is empty")
            sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to load wordlist: {e}")
        sys.exit(1)
    
    # Prepare headers
    headers = {
        'User-Agent': get_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    
    # Print scan information
    print(Fore.MAGENTA + "\n[~] Starting scan...")
    print(Fore.WHITE + f"[~] Target URL: {base_url}")
    print(Fore.WHITE + f"[~] Wordlist: {args.wordlist} ({len(paths)} entries)")
    print(Fore.WHITE + f"[~] Threads: {args.threads}")
    print(Fore.WHITE + f"[~] Timeout: {args.timeout}s")
    print(Fore.WHITE + f"[~] SSL Verification: {'Enabled' if args.no_ssl_verify else 'Disabled'}")
    print(Fore.WHITE + f"[~] Follow Redirects: {not args.no_redirects}")
    
    if args.output:
        print(Fore.WHITE + f"[~] Output file: {args.output}")
        # Clear the output file if it exists
        try:
            with open(args.output, 'w') as f:
                f.write(f"# drfuzzing scan results\n")
                f.write(f"# Target: {base_url}\n")
                f.write(f"# Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#" * 80 + "\n\n")
        except IOError as e:
            print(Fore.RED + f"[!] Warning: Could not write to output file: {e}")
    
    print(Fore.CYAN + "\n[!] Press Ctrl+C to stop the scan gracefully\n")
    
    # Track statistics
    start_time = time.time()
    processed = 0
    total = len(paths)
    
    # Create a queue for paths to process
    from queue import Queue
    path_queue = Queue()
    for path in paths:
        path_queue.put(path)
    
    # Worker function
    def worker():
        nonlocal processed
        while not stop_flag and not path_queue.empty():
            try:
                path = path_queue.get_nowait()
                check_path(
                    base_url, 
                    path, 
                    headers, 
                    args.output, 
                    args.timeout, 
                    args.no_ssl_verify, 
                    not args.no_redirects
                )
                with threading.Lock():
                    processed += 1
                    # Update progress every 10 requests
                    if processed % 10 == 0 or processed == total:
                        progress = (processed / total) * 100
                        elapsed = time.time() - start_time
                        req_per_sec = processed / elapsed if elapsed > 0 else 0
                        eta = (total - processed) / req_per_sec if req_per_sec > 0 else 0
                        
                        sys.stdout.write("\r" + Fore.WHITE + "[~] Progress: " + 
                                       f"{processed}/{total} ({progress:.1f}%) | " +
                                       f"{req_per_sec:.1f} req/s | " +
                                       f"ETA: {datetime.timedelta(seconds=int(eta))} | " +
                                       " " * 10)
                        sys.stdout.flush()
                        
            except Exception as e:
                if not stop_flag:
                    print(Fore.RED + f"[!] Worker error: {e}")
            finally:
                path_queue.task_done()
    
    # Start worker threads
    import threading
    threads = []
    for _ in range(min(args.threads, len(paths))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for all paths to be processed
    try:
        while any(t.is_alive() for t in threads) and not stop_flag:
            for t in threads:
                t.join(timeout=0.1)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Received interrupt signal. Waiting for active requests to complete...")
        stop_flag = True
        
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=2)
    
    # Calculate and display statistics
    elapsed = time.time() - start_time
    req_per_sec = processed / elapsed if elapsed > 0 else 0
    
    print("\n" + Fore.CYAN + "=" * 80)
    print(Fore.GREEN + f"[✓] Scan completed!")
    print(Fore.WHITE + f"[~] Total requests: {processed}")
    print(Fore.WHITE + f"[~] Time taken: {datetime.timedelta(seconds=int(elapsed))}")
    print(Fore.WHITE + f"[~] Requests per second: {req_per_sec:.1f}")
    print(Fore.CYAN + "=" * 80)
    
    if args.output:
        try:
            with open(args.output, 'a') as f:
                f.write("\n#" * 40 + "\n")
                f.write(f"# Scan completed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total requests: {processed}\n")
                f.write(f"# Time taken: {datetime.timedelta(seconds=int(elapsed))}\n")
                f.write(f"# Requests per second: {req_per_sec:.1f}\n")
            print(Fore.GREEN + f"[✓] Results saved to {args.output}")
        except IOError as e:
            print(Fore.RED + f"[!] Failed to write final statistics to output file: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] An unexpected error occurred: {e}")
        if hasattr(e, '__traceback__'):
            import traceback
            traceback.print_exc()
        sys.exit(1)