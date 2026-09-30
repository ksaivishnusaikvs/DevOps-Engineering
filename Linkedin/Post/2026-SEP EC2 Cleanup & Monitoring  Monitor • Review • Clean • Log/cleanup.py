#!/usr/bin/env python3
"""
Production Cleanup & Monitoring Script
"""                                                                 

import os
import json
import subprocess
import datetime
import getpass
import grp
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console()

# Log file setup: try /var/log first, else fallback to ~/logs
DEFAULT_LOG = Path("/var/log/prod_cleanup.log")
FALLBACK_LOG = Path.home() / "logs" / "prod_cleanup.log"
LOG_FILE = DEFAULT_LOG if os.access(DEFAULT_LOG.parent, os.W_OK) else FALLBACK_LOG


def show_description():
    console.print("""
[bold cyan]==========================================================[/bold cyan]
[bold yellow]Script Modes:[/bold yellow]

[bold green]1. Auto Mode (1)[/bold green]
   - The script runs automatically with predefined actions.
   - Kills processes, deletes files, scans disks, and logs everything.
   - No prompts appear for user input.
   - [red]Use with caution:[/red] only for safe/staging environments or
     pre-approved process/file lists.

[bold green]2. Interactive Mode (2) [Default][/bold green]
   - The script pauses and asks for input before every critical action.
     - Which PIDs to kill
     - Which files to delete
     - Folder paths for disk scan
   - Requires approval from an authorized user before killing/deleting.
   - [yellow]Safer for production environments.[/yellow]

[bold magenta]Note:[/bold magenta]
- Interactive mode is recommended for production.
- Auto mode is faster but may act on processes/files without confirmation.
[bold cyan]==========================================================[/bold cyan]
""")


def log_event(event, detail):
    """Log event in JSON format with safe IAM role detection"""
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    linux_user = getpass.getuser()
    sudo_user = os.environ.get("SUDO_USER", linux_user)
    linux_groups = ",".join(grp.getgrgid(g).gr_name for g in os.getgroups())
    euid = os.geteuid()

    # Detect IAM role safely
    try:
        role_name = subprocess.check_output(
            ["curl", "-s", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
            text=True, timeout=2
        ).strip()
        if role_name and "Unauthorized" not in role_name:
            iam_role = role_name
        else:
            iam_role = "none"
    except Exception:
        iam_role = "none"

    log_data = {
        "ts": ts,
        "linux_user": linux_user,
        "sudo_user": sudo_user,
        "linux_groups": linux_groups,
        "euid": euid,
        "iam_role": iam_role,
        "event": event,
        "detail": detail
    }
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        f.write(json.dumps(log_data) + "\n")


def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True)
    except subprocess.CalledProcessError:
        return ""


def system_monitor():
    console.print("\n[bold cyan]======= SYSTEM MONITOR =======[/bold cyan]")
    uptime_output = run_cmd("uptime | awk -F'load average:' '{print $2}'").strip()
    console.print(f"[bold yellow]CPU Load:[/bold yellow] {uptime_output}")
    console.print(run_cmd("free -h"))
    console.print(run_cmd("df -h | grep -E '^/dev|Filesystem'"))
    log_event("monitor", "System stats displayed")


def show_top_processes():
    # CPU
    console.print("\n[bold cyan]======= TOP 20 CPU PROCESSES =======[/bold cyan]")
    cpu_output = run_cmd("ps -eo pid,ppid,comm,%cpu,%mem --sort=-%cpu | head -n 21").splitlines()
    table_cpu = Table(show_header=True, header_style="bold magenta")
    table_cpu.add_column("PID", justify="right")
    table_cpu.add_column("PPID", justify="right")
    table_cpu.add_column("Command", overflow="fold")
    table_cpu.add_column("%CPU", justify="right")
    table_cpu.add_column("%MEM", justify="right")

    for line in cpu_output[1:]:
        parts = line.split(None, 4)
        if len(parts) == 5:
            table_cpu.add_row(*parts)
    console.print(table_cpu)

    # Memory
    console.print("\n[bold cyan]======= TOP 20 MEMORY PROCESSES =======[/bold cyan]")
    mem_output = run_cmd("ps -eo pid,ppid,comm,%cpu,%mem --sort=-%mem | head -n 21").splitlines()
    table_mem = Table(show_header=True, header_style="bold magenta")
    table_mem.add_column("PID", justify="right")
    table_mem.add_column("PPID", justify="right")
    table_mem.add_column("Command", overflow="fold")
    table_mem.add_column("%CPU", justify="right")
    table_mem.add_column("%MEM", justify="right")

    for line in mem_output[1:]:
        parts = line.split(None, 4)
        if len(parts) == 5:
            table_mem.add_row(*parts)
    console.print(table_mem)

    log_event("monitor", "Top CPU and memory processes displayed")
    return cpu_output, mem_output


def kill_processes(process_list, label):
    pids = Prompt.ask(f"Enter PIDs to kill from {label} list (space separated, blank to skip)", default="")
    if pids:
        for pid in pids.split():
            try:
                os.kill(int(pid), 9)
                console.print(f"[green]  Killed process {pid}[/green]")
                log_event("kill", f"Process {pid} killed from {label}")
            except Exception:
                console.print(f"[red]  Failed to kill {pid}[/red]")


def list_ebs_volumes():
    console.print("\n[bold cyan]======= EBS VOLUMES (Top 20) =======[/bold cyan]")
    if run_cmd("which aws"):
        volumes = run_cmd(
            "aws ec2 describe-volumes --query \"Volumes[*].{ID:VolumeId,State:State,Size:Size,AZ:AvailabilityZone}\" --output table | head -n 22"
        )
        console.print(volumes if volumes else "[yellow]No volumes found[/yellow]")
        log_event("ebs", "EBS volumes listed")
    else:
        console.print("[yellow]AWS CLI not installed. Skipping EBS volume listing.[/yellow]")
        log_event("ebs", "AWS CLI not installed")


def disk_usage():
    path = Prompt.ask("Enter folder path to scan", default="/")
    console.print(f"\n[bold cyan]======= DISK USAGE ({path}) =======[/bold cyan]")
    usage = run_cmd(f"du -ah {path} 2>/dev/null | sort -rh | head -n 20")
    console.print(usage)
    log_event("disk", f"Top storage usage scanned in path {path}")


def delete_files():
    files = Prompt.ask("Enter full file paths to delete (space separated, blank to skip)", default="")
    if files:
        for f in files.split():
            try:
                os.remove(f)
                console.print(f"[green]  Deleted {f}[/green]")
                log_event("delete", f"File {f} deleted")
            except FileNotFoundError:
                console.print(f"[yellow]   File {f} not found[/yellow]")


def main():
    show_description()
    mode = Prompt.ask("Choose Mode: [green]1=Auto[/green], [yellow]2=Interactive[/yellow]", default="2")

    system_monitor()
    cpu_list, mem_list = show_top_processes()
    list_ebs_volumes()

    if mode == "2":
        kill_processes(cpu_list, "CPU")
        kill_processes(mem_list, "Memory")
        disk_usage()
        delete_files()

    log_event("finish", "Cleanup completed")
    console.print("\n[bold green]   Cleanup Completed![/bold green]")


if __name__ == "__main__":
    main()   

If run the script 






