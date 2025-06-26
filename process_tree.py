import os
import json
import argparse

class ProcessNode:
    def __init__(self, process_id, parent_process_id, image, command_line):
        self.process_id = process_id
        self.parent_process_id = parent_process_id
        self.image = image.lower() if image else ""
        self.command_line = command_line.lower() if command_line else ""
        self.children = []
        self.alerts = []

    def add_child(self, child_node):
        self.children.append(child_node)

    def check_suspicious(self, parent_node=None):
        # Rule 1: Encoded PowerShell detection
        if "powershell.exe" in self.image and "-enc" in self.command_line:
            self.alerts.append("PowerShell with encoded command detected")

        # Rule 2: Suspicious parent-child relationships
        if parent_node:
            parent = parent_node.image
            child = self.image
            suspicious_chains = [
                ("explorer.exe", "cmd.exe"),
                ("cmd.exe", "powershell.exe"),
                ("powershell.exe", "rundll32.exe"),
            ]
            if (parent, child) in suspicious_chains:
                self.alerts.append(f"Suspicious parent-child process chain: {parent} -> {child}")

        # Rule 3: Suspicious process launch locations
        suspicious_paths = [
            "\\appdata\\roaming",
            "\\appdata\\local",
            "\\temp",
            "\\downloads",
            "\\windows\\temp",
        ]
        for spath in suspicious_paths:
            if spath in self.image:
                self.alerts.append(f"Process launched from suspicious location: {spath}")
                break  # Only one alert per process for location

        # Rule 4: Suspicious network commands
        network_commands = [
            "invoke-webrequest",
            "invoke-restmethod",
            "curl",
            "wget",
            "bitsadmin",
            "certutil -urlcache"
        ]

        for cmd in network_commands:
            if cmd in self.command_line:
                self.alerts.append(f"Suspicious network command detected: {cmd}")
                break

        # Recursively check children
        for child in self.children:
            child.check_suspicious(self)

    def print_tree(self, level=0):
        indent = "  " * level
        alert_str = ""
        if self.alerts:
            alert_str = "  🚩 ALERT: " + "; ".join(self.alerts)
        print(f"{indent}- [PID {self.process_id}] {self.image} : {self.command_line}{alert_str}")
        for child in self.children:
            child.print_tree(level + 1)

def build_process_tree(logs):
    nodes = {}
    for event in logs:
        pid = event.get("ProcessId")
        ppid = event.get("ParentProcessId")
        image = event.get("Image")
        cmd = event.get("CommandLine")
        if pid is None:
            continue
        node = ProcessNode(pid, ppid, image, cmd)
        nodes[pid] = node

    # Link children to parents
    for pid, node in nodes.items():
        parent_id = node.parent_process_id
        if parent_id in nodes:
            nodes[parent_id].add_child(node)

    # Find roots
    roots = [node for pid, node in nodes.items() if node.parent_process_id not in nodes]
    return roots

def write_report(roots, report_path):
    with open(report_path, "w") as report_file:
        report_file.write("=== Suspicious Behavior Detection Report ===\n\n")
        def write_alerts(node):
            if node.alerts:
                alerts_text = "; ".join(node.alerts)
                report_file.write(f"PID {node.process_id} | {node.image} | {node.command_line}\n")
                report_file.write(f"  ALERTS: {alerts_text}\n\n")
            for child in node.children:
                write_alerts(child)
        for root in roots:
            write_alerts(root)

def main():
    parser = argparse.ArgumentParser(description="Suspicious Process & Behavior Analyzer")
    parser.add_argument("-i", "--input", type=str, default=None,
                        help="Path to JSON log file to analyze")
    parser.add_argument("-r", "--report", type=str, default=None,
                        help="Path to output report file (optional)")
    parser.add_argument("--no-report", action="store_true",
                        help="Disable report file generation")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose console output")

    args = parser.parse_args()

    # Determine input file
    if args.input:
        input_path = args.input
    else:
        # Default path relative to script location
        base_dir = os.path.dirname(__file__)
        input_path = os.path.join(base_dir, "sample_logs", "sample_sysmon.json")

    # Load logs
    try:
        with open(input_path, "r") as file:
            logs = json.load(file)
    except Exception as e:
        print(f"Error loading input file: {e}")
        return

    roots = build_process_tree(logs)

    # Check suspicious behavior
    for root in roots:
        root.check_suspicious()

    print("=== Process Tree with Suspicious Behavior Detection ===")
    for root in roots:
        root.print_tree()

    # Handle report output
    if not args.no_report:
        if args.report:
            report_path = args.report
        else:
            base_dir = os.path.dirname(__file__)
            report_path = os.path.join(base_dir, "detection_report.txt")

        write_report(roots, report_path)
        print(f"\nReport written to {report_path}")

if __name__ == "__main__":
    main()
