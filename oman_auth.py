import re
import json
import argparse
from datetime import datetime

def check_hours(line):
    try:
        timestamp_str = " ".join(line.split()[:3])
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        return timestamp.hour < 5 or timestamp.hour > 22
    except ValueError:
        return False

def parse_logs(log_file):
    rules = {
        "Failed SSH Login": r"Failed password for invalid user (\w+)",
        "Unexpected Admin Login": r"Accepted password for admin from",
        "Malicious Domain": r"connection to suspicious-domain\.com",
        "Command Execution": r"user ran suspicious command: (.+)",
        "Unusual Hours": lambda line: check_hours(line)
    }
    results = []
    with open(log_file, "r") as f:
        for line in f:
            for tag, pattern in rules.items():
                if callable(pattern):
                    if pattern(line):
                        results.append({"IOC": tag, "log": line.strip()})
                elif re.search(pattern, line):
                    results.append({"IOC": tag, "log": line.strip()})
    return results

def print_findings(results):
    print("Log Parser Results:\n")
    for entry in results:
        print(f"[{entry['IOC']}] {entry['log']}")
    print(f"\nTotal Findings: {len(results)}")

def export_report(results, filename="log_report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nExported report to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Parser")
    parser.add_argument("log_file", help="Path to the log file to be parsed")
    args = parser.parse_args()

    findings = parse_logs(args.log_file)
    print_findings(findings)
    export_report(findings)
