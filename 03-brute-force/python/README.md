# Brute Force Tool — Python

A multi-threaded brute force tool for SSH and FTP services, built with Paramiko and ftplib.

## Features

- SSH and FTP brute forcing
- Multi-threaded for speed
- Timestamps on all attempts
- Stops immediately when password is found
- Save results to a log file (`-o`)

## Requirements

```
sudo apt install python3-paramiko
```

## Usage

```bash
python3 bruteforce.py -t <target> -u <username> -w <wordlist> [options]
```

| Flag | Description |
|------|-------------|
| `-t` | Target IP address |
| `-u` | Username to attack |
| `-w` | Path to password wordlist |
| `-s` | Service: `ssh` or `ftp` (default: ssh) |
| `-p` | Port (default: 22 for SSH, 21 for FTP) |
| `-T` | Number of threads (default: 4) |
| `-o` | Save output to a log file |

## Examples

SSH brute force:
```bash
python3 bruteforce.py -t 192.168.0.240 -u cletus -w wordlist.txt -s ssh -T 4
```

FTP brute force with log output:
```bash
python3 bruteforce.py -t 192.168.0.240 -u cletus -w wordlist.txt -s ftp -o results.log
```

## Sample Output

```
[*] Target   : 192.168.0.240:22
[*] Service  : SSH
[*] Username : cletus
[*] Wordlist : wordlist.txt
[*] Threads  : 4

[21:59:09] [-] Failed: admin
[21:59:09] [-] Failed: password
[21:59:09] [-] Failed: 123456
[21:59:09] [-] Failed: letmein
[21:59:09] [+] SUCCESS! Password found: password123
```

## How It Works

Each thread picks a password from the wordlist and attempts a login. For SSH, Paramiko raises `AuthenticationException` on failure. For FTP, `ftplib` raises `error_perm`. A threading `Event` flag stops all threads the moment the password is found.

> **Note:** Only use against systems you own or have explicit written permission to test.
