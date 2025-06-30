import os
import sys
import subprocess
import re
import shutil
import requests

def run_command(cmd, output_file=None):
    print(f"\n[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if output_file:
        with open(output_file, "w") as f:
            f.write(result.stdout)
    print(result.stdout)
    return result.stdout

def scan_ports(target, loot_dir):
    rustscan = shutil.which("rustscan")
    if rustscan:
        print("[*] Using rustscan for fast scanning...")
        cmd = f"rustscan -a {target} --ultra-fast -- -Pn -n -sS -T5"
    else:
        print("[*] Using nmap for full port scan...")
        cmd = f"nmap -p- -T5 -Pn -v {target}"
    output = run_command(cmd, f"{loot_dir}/nmap.txt")
    return output

def extract_ports(nmap_output):
    ports = []
    for line in nmap_output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open", line)
        if match:
            ports.append(int(match.group(1)))
    return ports

def is_web_alive(target, port):
    proto = "https" if port == 443 else "http"
    try:
        r = requests.get(f"{proto}://{target}:{port}", timeout=5)
        return r.status_code < 500
    except:
        return False

def run_ffuf(target, port, wordlist, loot_dir):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}:{port}/FUZZ"
    output = f"{loot_dir}/ffuf_{port}.json"
    cmd = f"ffuf -u {url} -w {wordlist} -mc all -t 100 -o {output}"
    run_command(cmd)

def waybackurls(target, loot_dir):
    cmd = f"waybackurls {target}"
    run_command(cmd, f"{loot_dir}/wayback.txt")

def arjun_scan(target, port, loot_dir):
    url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
    cmd = f"arjun -u {url} -oT {loot_dir}/arjun_{port}.txt"
    run_command(cmd)

def subdomain_enum(domain, loot_dir):
    cmd = f"subfinder -d {domain} -silent"
    run_command(cmd, f"{loot_dir}/subdomains.txt")

def screenshot_web(target, port, loot_dir):
    url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
    screen_dir = f"{loot_dir}/screens"
    os.makedirs(screen_dir, exist_ok=True)
    cmd = f"gowitness single --url {url} --out {screen_dir}"
    run_command(cmd)

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        print("Usage: python3 script.py <target>")
        sys.exit(1)

    inpu = input("Enter file name to log raw command output (e.g. eni.txt): ").strip()
    wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"

    if not os.path.exists(wordlist):
        print("[-] Wordlist not found. Please update the wordlist path.")
        sys.exit(1)

    loot_dir = f"loot/{target}"
    os.makedirs(loot_dir, exist_ok=True)

    print(f"[+] Target: {target}")

    port_output = scan_ports(target, loot_dir)
    with open(inpu, "w") as f:
        f.write(port_output)

    open_ports = extract_ports(port_output)
    print(f"[+] Open ports: {open_ports}")

    with open(f"{loot_dir}/ports.txt", "w") as f:
        f.write("\n".join(map(str, open_ports)))

    for port in [80, 443, 8080]:
        if port in open_ports and is_web_alive(target, port):
            print(f"[+] Port {port} is live. Running ffuf, arjun, and screenshot...")
            run_ffuf(target, port, wordlist, loot_dir)
            arjun_scan(target, port, loot_dir)
            screenshot_web(target, port, loot_dir)

    waybackurls(target, loot_dir)
    subdomain_enum(target, loot_dir)

if __name__ == "__main__":
    main()
