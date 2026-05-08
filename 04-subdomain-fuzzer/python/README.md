# Directory Fuzzer — Python

A multi-threaded web directory and file fuzzer with HTML report generation. Discovers hidden directories and sensitive files on web servers.

## Features

- Directory fuzzing — finds hidden paths (`/admin`, `/backup`, `/login`)
- File extension discovery — finds hidden files (`.php`, `.bak`, `.txt`, `.zip`)
- Response code filtering — reports 200, 301, 302, 403 and skips 404
- Multi-threaded for speed
- Professional HTML report with colour-coded results
- Save raw output to log file (`-o`)

## Requirements

```
pip3 install requests
```

## Usage

```bash
python3 fuzzer.py -t <target> -w <wordlist> [options]
```

| Flag | Description |
|------|-------------|
| `-t` | Target URL (e.g. `http://192.168.0.240`) |
| `-w` | Path to wordlist |
| `-e` | File extensions to check (e.g. `php,bak,txt`) |
| `-T` | Number of threads (default: 10) |
| `-o` | Save raw output to log file |
| `-r` | Generate HTML report |

## Examples

Basic directory scan:
```bash
python3 fuzzer.py -t http://192.168.0.240 -w wordlist.txt
```

Scan with file extensions and HTML report:
```bash
python3 fuzzer.py -t http://192.168.0.240 -w wordlist.txt -e php,bak,txt -T 10 -r report.html
```

Fuzz inside a discovered directory:
```bash
python3 fuzzer.py -t http://192.168.0.240/backup -w wordlist.txt -e php,bak,txt -r report_backup.html
```

## Sample Output

```
[*] Target    : http://192.168.0.240
[*] Wordlist  : wordlist.txt
[*] Extensions: ['php', 'bak', 'txt']
[*] Threads   : 10

[11:34:52] [301] [REDIRECT] http://192.168.0.240/backup  (315 bytes)
[11:34:53] [301] [REDIRECT] http://192.168.0.240/admin  (314 bytes)
[11:34:53] [200] [FOUND]    http://192.168.0.240/backup/config.bak  (27 bytes)

[*] Finished. 3 results found.
[*] HTML report saved to report.html
```

## How It Works

For each word in the wordlist, the fuzzer sends an HTTP GET request to `target/word` and checks the response code. It also appends each specified extension (`word.php`, `word.bak` etc.) to catch hidden files. Threading allows multiple requests to run simultaneously for speed. Results are colour-coded in the HTML report — green for 200, orange for redirects, red for forbidden pages.

> **Note:** Only use against web servers you own or have explicit written permission to test.
