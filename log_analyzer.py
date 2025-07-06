import argparse
import re
from collections import defaultdict

suspicious_patterns = {
    "SQL Injection": r"('|%27|\b(UNION|SELECT|INSERT|UPDATE|DROP|OR 1=1)\b)",
    "XSS": r"(<script>|%3Cscript%3E)",
    "Directory Traversal": r"\.\./|\%2e\%2e"
}

ip_count = defaultdict(int)
flagged_requests = []

def analyze_log(logfile):
    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                ip_count[ip] += 1

            for attack_type, pattern in suspicious_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    flagged_requests.append((attack_type, line.strip()))
                    break

def generate_report(output_file=None):
    print("\n🛡️ Top IPs by Request Count:")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{ip} → {count} requests")

    print("\n🚨 Suspicious Requests Found:")
    for attack, line in flagged_requests:
        print(f"[{attack}] {line[:100]}...")

    if output_file:
        with open(output_file, "w") as f:
            f.write("Top IPs:\n")
            for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"{ip} → {count} requests\n")

            f.write("\nSuspicious Requests:\n")
            for attack, line in flagged_requests:
                f.write(f"[{attack}] {line}\n")

        print(f"\n📁 Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="🧠 Log Analyzer - Detect Suspicious IPs and Attacks")
    parser.add_argument("-f", "--file", required=True, help="Path to web server access log file")
    parser.add_argument("-o", "--output", help="Output file to save report")
    args = parser.parse_args()

    analyze_log(args.file)
    generate_report(args.output)

if __name__ == "__main__":
    main()
