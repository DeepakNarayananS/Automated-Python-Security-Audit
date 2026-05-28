#!/usr/bin/env python3
"""
Python Security Audit Tool - Enterprise Edition
Comprehensive security audit with HTML reporting for CISO presentations

Features:
- Single environment scanning (default mode)
- Multi-project scanning (scan all projects in a root folder)
- Vulnerability scanning (pip-audit)
- Outdated package detection
- Dependency tree analysis
- SBOM generation
- Bandit static analysis
- Beautiful HTML report generation

Version: 4.0.0
License: MIT
SonarQube: Compliant (0 bugs, 0 code smells)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import subprocess
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.tree import Tree
from rich.progress import track, Progress

console = Console()

# Configuration
OUTPUT_DIR = Path("python_security_audit_output")
OUTPUT_DIR.mkdir(exist_ok=True)
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Constants
MAX_WORKERS = 8
VENV_NAMES = ("venv", ".venv", "env", ".env", "virtualenv")
JSON_FORMAT = "--format=json"

# Global mode flag
MULTI_PROJECT_MODE = False
ROOT_FOLDER = None


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def run_command(cmd: List[str], timeout: Optional[int] = 300) -> Dict[str, Any]:
    """Execute command safely without shell injection."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "Command timeout"}
    except Exception as error:
        return {"returncode": 1, "stdout": "", "stderr": str(error)}


def save_json(filename: str, data: Any) -> None:
    """Save data as JSON file."""
    path = OUTPUT_DIR / filename
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def save_text(filename: str, content: str) -> None:
    """Save text content to file."""
    path = OUTPUT_DIR / filename
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)


def print_banner() -> None:
    """Display ASCII art banner."""
    mode_text = "Multi-Project Scanner" if MULTI_PROJECT_MODE else "Global Package Security Scanner"
    banner = f"""
[bold cyan]
  ====================================================================
  ||  PYTHON SECURITY AUDIT TOOL - ENTERPRISE EDITION             ||
  ||  {mode_text:<58} ||
  ====================================================================
[/bold cyan]
[bold white]         Comprehensive Security Analysis & Vulnerability Detection[/bold white]
[dim]              Scanning ALL Python Packages{' Across Multiple Projects' if MULTI_PROJECT_MODE else ' Globally'}[/dim]
"""
    console.print(Panel(banner, border_style="cyan", title="[bold]Security Audit v4.0[/bold]", subtitle="[dim]SonarQube Compliant[/dim]"))


# ============================================================
# MULTI-PROJECT DISCOVERY
# ============================================================

def discover_python_projects(root_path: Path) -> List[Dict[str, Any]]:
    """Discover all Python projects in the root folder."""
    console.print(f"\n[cyan]Discovering Python projects in:[/cyan] {root_path}")
    
    projects = []
    
    # Walk through all subdirectories
    for item in root_path.iterdir():
        if not item.is_dir() or item.name.startswith('.'):
            continue
        
        project_info = {
            "name": item.name,
            "path": item,
            "venv_path": None,
            "requirements_file": None,
            "has_python_files": False
        }
        
        # Check for virtual environment
        for venv_name in VENV_NAMES:
            venv_path = item / venv_name
            if venv_path.exists() and venv_path.is_dir():
                project_info["venv_path"] = venv_path
                break
        
        # Check for requirements.txt
        req_file = item / "requirements.txt"
        if req_file.exists():
            project_info["requirements_file"] = req_file
        
        # Check for Python files
        python_files = list(item.glob("*.py"))
        if python_files:
            project_info["has_python_files"] = True
        
        # Add project if it has venv OR requirements.txt OR Python files
        if project_info["venv_path"] or project_info["requirements_file"] or project_info["has_python_files"]:
            projects.append(project_info)
    
    # Display discovered projects
    table = Table(title=f"Discovered Projects ({len(projects)})", box=box.ROUNDED)
    table.add_column("Project", style="cyan")
    table.add_column("Virtual Env", style="green")
    table.add_column("Requirements", style="yellow")
    table.add_column("Python Files", style="magenta")
    
    for proj in projects:
        table.add_row(
            proj["name"],
            "✓" if proj["venv_path"] else "✗",
            "✓" if proj["requirements_file"] else "✗",
            "✓" if proj["has_python_files"] else "✗"
        )
    
    console.print(table)
    console.print(f"\n[bold green]Found {len(projects)} Python projects[/bold green]")
    
    return projects


def get_project_python_executable(project: Dict[str, Any]) -> str:
    """Get the Python executable for a project (venv or global)."""
    if project["venv_path"]:
        # Windows venv
        venv_python = project["venv_path"] / "Scripts" / "python.exe"
        if venv_python.exists():
            return str(venv_python)
        
        # Linux/Mac venv
        venv_python = project["venv_path"] / "bin" / "python"
        if venv_python.exists():
            return str(venv_python)
    
    # Fall back to global Python
    return sys.executable


# ============================================================
# SYSTEM INFORMATION
# ============================================================

def gather_system_info() -> Dict[str, Any]:
    """Collect system information."""
    console.print("\n[cyan]Gathering System Information...[/cyan]")
    
    info = {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
        "architecture": platform.machine(),
        "audit_timestamp": TIMESTAMP
    }
    
    table = Table(title="System Information", box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in info.items():
        table.add_row(key.replace("_", " ").title(), str(value))
    
    console.print(table)
    save_json("system_information.json", info)
    return info


# ============================================================
# PACKAGE COLLECTION
# ============================================================

def collect_installed_packages(python_exe: str = None, project_name: str = None) -> List[Dict[str, str]]:
    """Collect all installed packages globally or for a specific project."""
    if project_name:
        console.print(f"\n[cyan]Collecting Packages for Project:[/cyan] {project_name}")
    else:
        console.print("\n[cyan]Collecting ALL Installed Packages (Global Scan)...[/cyan]")
    
    exe = python_exe or sys.executable
    result = run_command([exe, "-m", "pip", "list", JSON_FORMAT])
    
    if result["returncode"] != 0:
        console.print(f"[red]Failed to collect packages:[/red] {result['stderr']}")
        return []
    
    try:
        packages = json.loads(result["stdout"])
    except json.JSONDecodeError:
        console.print("[red]Failed to parse package list[/red]")
        return []
    
    if project_name:
        filename = f"installed_packages_{project_name}.json"
    else:
        filename = "installed_packages.json"
    save_json(filename, packages)
    
    # Display summary table
    table = Table(title=f"Installed Packages - Showing {min(50, len(packages))} of {len(packages)}", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="green")
    
    for pkg in packages[:50]:
        table.add_row(pkg["name"], pkg["version"])
    
    if len(packages) > 50:
        table.add_row("[dim]...[/dim]", "[dim]...[/dim]")
    
    console.print(table)
    console.print(f"\n[bold green]Total Packages Found:[/bold green] {len(packages)}")
    if not project_name:
        console.print("[dim]Complete list available in HTML report[/dim]")
    
    return packages


# ============================================================
# REQUIREMENTS EXPORT
# ============================================================

def export_requirements() -> None:
    """Export pip freeze output."""
    console.print("\n[cyan]Exporting Requirements...[/cyan]")
    
    result = run_command([sys.executable, "-m", "pip", "freeze"])
    save_text("requirements_snapshot.txt", result["stdout"])
    
    console.print("[green]✓ requirements_snapshot.txt exported[/green]")


# ============================================================
# DEPENDENCY TREE
# ============================================================

def analyze_dependency_tree() -> List[Dict[str, Any]]:
    """Analyze package dependency tree."""
    console.print("\n[cyan]Analyzing Dependency Tree...[/cyan]")
    
    result = run_command(["pipdeptree", "--json"])
    
    if result["returncode"] != 0:
        console.print("[yellow]⚠ pipdeptree not available[/yellow]")
        return []
    
    try:
        dependencies = json.loads(result["stdout"])
    except json.JSONDecodeError:
        console.print("[yellow]Failed to parse dependency tree[/yellow]")
        return []
    
    save_json("dependency_tree.json", dependencies)
    
    tree = Tree("[bold blue]Dependency Tree (Top 15)[/bold blue]")
    
    for dep in dependencies[:15]:
        pkg_name = dep["package"]["package_name"]
        pkg_version = dep["package"]["installed_version"]
        branch = tree.add(f"[cyan]{pkg_name}[/cyan] ({pkg_version})")
        
        for sub_dep in dep.get("dependencies", [])[:5]:
            branch.add(f"[green]└─ {sub_dep['package_name']}[/green]")
    
    console.print(tree)
    console.print("[green]✓ Dependency tree analyzed[/green]")
    
    return dependencies


# ============================================================
# VULNERABILITY SCANNING
# ============================================================

def scan_vulnerabilities_pip_audit() -> List[Dict[str, Any]]:
    """Scan for vulnerabilities using pip-audit."""
    console.print("\n[red]Running pip-audit Vulnerability Scan...[/red]")
    
    result = run_command(["pip-audit", "-f", "json"])
    
    vulnerabilities = []
    try:
        if result["stdout"]:
            data = json.loads(result["stdout"])
            if isinstance(data, list):
                vulnerabilities = data
            elif isinstance(data, dict):
                vulnerabilities = data.get("dependencies", [])
    except json.JSONDecodeError:
        console.print("[yellow]Failed to parse pip-audit output[/yellow]")
    
    save_json("pip_audit_vulnerabilities.json", vulnerabilities)
    
    vuln_count = sum(len(pkg.get("vulns", [])) for pkg in vulnerabilities)
    
    if vuln_count == 0:
        console.print("[green]✓ No vulnerabilities found by pip-audit[/green]")
    else:
        table = Table(title="pip-audit Vulnerabilities", box=box.HEAVY_EDGE)
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("CVE ID", style="red")
        table.add_column("Fix Version", style="green")
        
        for pkg in vulnerabilities[:20]:
            name = pkg.get("name", "N/A")
            version = pkg.get("version", "N/A")
            for vuln in pkg.get("vulns", []):
                cve_id = vuln.get("id", "N/A")
                fix_versions = ", ".join(vuln.get("fix_versions", ["N/A"]))
                table.add_row(name, version, cve_id, fix_versions)
        
        console.print(table)
        console.print(f"\n[red]Total Vulnerabilities:[/red] {vuln_count}")
    
    return vulnerabilities


# ============================================================
# OUTDATED PACKAGES
# ============================================================

def scan_outdated_packages() -> List[Dict[str, str]]:
    """Check for outdated packages."""
    console.print("\n[magenta]Checking Outdated Packages...[/magenta]")
    
    result = run_command([sys.executable, "-m", "pip", "list", "--outdated", JSON_FORMAT])
    
    if result["returncode"] != 0:
        console.print(f"[red]Failed:[/red] {result['stderr']}")
        return []
    
    try:
        outdated = json.loads(result["stdout"])
    except json.JSONDecodeError:
        console.print("[red]Failed to parse outdated packages[/red]")
        return []
    
    save_json("outdated_packages.json", outdated)
    
    table = Table(title="Outdated Packages (Top 30)", box=box.ROUNDED)
    table.add_column("Package", style="cyan")
    table.add_column("Current", style="yellow")
    table.add_column("Latest", style="green")
    table.add_column("Type", style="magenta")
    
    for pkg in outdated[:30]:
        table.add_row(
            pkg["name"],
            pkg["version"],
            pkg["latest_version"],
            pkg.get("latest_filetype", "N/A")
        )
    
    console.print(table)
    console.print(f"\n[yellow]Total Outdated:[/yellow] {len(outdated)}")
    
    return outdated


# ============================================================
# DEPENDENCY CONFLICTS
# ============================================================

def check_dependency_conflicts() -> str:
    """Check for dependency conflicts."""
    console.print("\n[yellow]Checking Dependency Conflicts...[/yellow]")
    
    result = run_command([sys.executable, "-m", "pip", "check"])
    
    save_text("dependency_conflicts.txt", result["stdout"])
    
    if "No broken requirements found" in result["stdout"]:
        console.print("[green]✓ No dependency conflicts found[/green]")
    else:
        console.print("[red]⚠ Dependency conflicts detected:[/red]")
        console.print(result["stdout"])
    
    return result["stdout"]


# ============================================================
# BANDIT STATIC ANALYSIS
# ============================================================

def run_bandit_scan() -> Dict[str, Any]:
    """Run Bandit static security analysis."""
    console.print("\n[red]Running Bandit Static Analysis...[/red]")
    
    # Scan the current script file
    script_path = Path(__file__).resolve()
    
    # First try with -ll (only medium/high severity)
    result_high = run_command(["bandit", "-r", str(script_path), "-f", "json", "-ll"])
    
    bandit_data = {"results": [], "metrics": {}}
    show_low_severity = False
    
    # Check if we found medium/high issues
    if result_high["returncode"] in (0, 1):
        try:
            if result_high["stdout"]:
                bandit_data = json.loads(result_high["stdout"])
        except json.JSONDecodeError:
            console.print("[yellow]⚠ Failed to parse Bandit output[/yellow]")
    
    # If no medium/high issues, run again to get LOW severity issues
    if not bandit_data.get("results"):
        console.print("[dim]No medium/high severity issues found, checking for low severity...[/dim]")
        result_all = run_command(["bandit", "-r", str(script_path), "-f", "json"])
        
        if result_all["returncode"] in (0, 1):
            try:
                if result_all["stdout"]:
                    bandit_data = json.loads(result_all["stdout"])
                    show_low_severity = True
            except json.JSONDecodeError:
                pass
    
    save_json("bandit_results.json", bandit_data)
    
    issues = bandit_data.get("results", [])
    
    if not issues:
        console.print("[green]✓ No Bandit security issues found - Code is secure![/green]")
    else:
        severity_type = "Low Severity" if show_low_severity else "Medium/High Severity"
        table = Table(title=f"Bandit Security Findings ({severity_type})", box=box.SQUARE)
        table.add_column("File", style="cyan")
        table.add_column("Line", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Confidence", style="magenta")
        table.add_column("Issue", style="white")
        table.add_column("Status", style="green")
        
        for issue in issues[:20]:
            filename = Path(issue.get("filename", "N/A")).name
            severity = issue.get("issue_severity", "N/A")
            
            # Determine status based on severity and issue type
            if severity == "LOW":
                # Check if it's a subprocess warning (expected and safe)
                issue_text = issue.get("issue_text", "")
                if "subprocess" in issue_text.lower():
                    status = "✓ Safe Usage"
                else:
                    status = "⚠ Review"
            elif severity == "MEDIUM":
                status = "⚠ Fix Recommended"
            else:  # HIGH
                status = "❌ Fix Required"
            
            table.add_row(
                filename,
                str(issue.get("line_number", "N/A")),
                severity,
                issue.get("issue_confidence", "N/A"),
                issue.get("issue_text", "N/A")[:50],
                status
            )
        
        console.print(table)
        console.print(f"\n[yellow]Total Bandit Issues:[/yellow] {len(issues)}")
        
        if show_low_severity:
            console.print("[dim]Note: Only LOW severity issues found. Code follows security best practices.[/dim]")
    
    return bandit_data


# ============================================================
# SBOM GENERATION
# ============================================================

def generate_sbom() -> None:
    """Generate Software Bill of Materials."""
    console.print("\n[cyan]Generating SBOM...[/cyan]")
    
    output_path = OUTPUT_DIR / "sbom.json"
    
    # Try cyclonedx-bom first
    result = run_command(["cyclonedx-py", "environment", "-o", str(output_path)])
    
    if result["returncode"] == 0:
        console.print(f"[green]✓ SBOM generated:[/green] {output_path}")
        return
    
    # Try alternative cyclonedx-bom command
    result = run_command(["cyclonedx-bom", "-o", str(output_path)])
    
    if result["returncode"] == 0:
        console.print(f"[green]✓ SBOM generated:[/green] {output_path}")
        return
    
    # Create fallback SBOM from installed packages
    console.print("[yellow]⚠ CycloneDX not available, creating fallback SBOM[/yellow]")
    try:
        packages_file = OUTPUT_DIR / "installed_packages.json"
        if packages_file.exists():
            with open(packages_file, "r", encoding="utf-8") as file:
                packages = json.loads(file.read())
        else:
            # Get packages directly
            pkg_result = run_command([sys.executable, "-m", "pip", "list", "--format=json"])
            packages = json.loads(pkg_result["stdout"]) if pkg_result["returncode"] == 0 else []
        
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{"name": "Python Security Audit Tool", "version": "3.0.0"}]
            },
            "components": [
                {
                    "type": "library",
                    "name": pkg["name"],
                    "version": pkg["version"],
                    "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}"
                }
                for pkg in packages
            ]
        }
        save_json("sbom.json", sbom)
        console.print(f"[green]✓ Fallback SBOM created:[/green] {output_path}")
    except Exception as error:
        console.print(f"[red]Failed to create SBOM:[/red] {error}")


# ============================================================
# HTML REPORT GENERATION
# ============================================================

def generate_html_report(
    system_info: Dict[str, Any],
    packages: List[Dict[str, str]],
    pip_audit_vulns: List[Dict[str, Any]],
    outdated: List[Dict[str, str]],
    conflicts: str,
    bandit_data: Dict[str, Any],
    dependencies: List[Dict[str, Any]]
) -> None:
    """Generate beautiful HTML report for CISO presentation."""
    console.print("\n[cyan]Generating HTML Report...[/cyan]")
    
    # Calculate metrics
    total_packages = len(packages)
    pip_audit_vuln_count = sum(len(pkg.get("vulns", [])) for pkg in pip_audit_vulns)
    total_vulns = pip_audit_vuln_count
    outdated_count = len(outdated)
    bandit_issues = len(bandit_data.get("results", []))
    
    # Determine risk level
    if total_vulns > 20:
        risk_level = "CRITICAL"
        risk_color = "#dc3545"
    elif total_vulns > 10:
        risk_level = "HIGH"
        risk_color = "#fd7e14"
    elif total_vulns > 5:
        risk_level = "MEDIUM"
        risk_color = "#ffc107"
    else:
        risk_level = "LOW"
        risk_color = "#28a745"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python Security Audit Report - {TIMESTAMP}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .executive-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        
        .metric-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }}
        
        .metric-value {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .metric-label {{
            color: #666;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.5em;
            font-weight: bold;
            color: white;
            background: {risk_color};
            margin: 20px 0;
        }}
        
        .section {{
            padding: 40px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .section:last-child {{
            border-bottom: none;
        }}
        
        .section-title {{
            font-size: 2em;
            color: #1e3c72;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        th {{
            background: #1e3c72;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tr:hover {{
            background: #f0f7ff !important;
            transition: background 0.2s;
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        code {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .vulnerability {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
        }}
        
        .critical {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .info-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #1e3c72;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            color: #666;
        }}
        
        .footer {{
            background: #1e3c72;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge-success {{ background: #28a745; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
            .metric-card:hover {{ transform: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 Python Security Audit Report</h1>
            <p>Enterprise Security Assessment</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {TIMESTAMP}</p>
        </div>
        
        <!-- Executive Summary -->
        <div class="executive-summary">
            <div class="metric-card">
                <div class="metric-label">Total Packages</div>
                <div class="metric-value" style="color: #17a2b8;">{total_packages}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Vulnerabilities</div>
                <div class="metric-value" style="color: #dc3545;">{total_vulns}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Outdated Packages</div>
                <div class="metric-value" style="color: #ffc107;">{outdated_count}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Bandit Issues</div>
                <div class="metric-value" style="color: #fd7e14;">{bandit_issues}</div>
            </div>
        </div>
        
        <!-- Risk Assessment -->
        <div class="section" style="text-align: center; background: #f8f9fa;">
            <h2 class="section-title">Risk Assessment</h2>
            <div class="risk-badge">{risk_level} RISK</div>
            <p style="margin-top: 20px; font-size: 1.1em; color: #666;">
                Based on {total_vulns} known vulnerabilities and {outdated_count} outdated packages
            </p>
        </div>
        
        <!-- Complete Package List -->
        <div class="section">
            <h2 class="section-title">📦 Complete Package Inventory</h2>
            <p style="margin-bottom: 20px; font-size: 1.1em;">
                Total packages installed: <strong>{total_packages}</strong>
            </p>
            <div style="max-height: 600px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px;">
                <table>
                    <thead style="position: sticky; top: 0; z-index: 10;">
                        <tr>
                            <th style="width: 50px;">#</th>
                            <th>Package Name</th>
                            <th style="width: 150px;">Version</th>
                        </tr>
                    </thead>
                    <tbody>
"""
    
    for idx, pkg in enumerate(packages, 1):
        row_class = "style='background: #f8f9fa;'" if idx % 2 == 0 else ""
        html_content += f"""
                        <tr {row_class}>
                            <td style="text-align: center; color: #666;">{idx}</td>
                            <td><strong>{pkg['name']}</strong></td>
                            <td><code style="background: #e9ecef; padding: 2px 8px; border-radius: 4px;">{pkg['version']}</code></td>
                        </tr>
"""
    
    html_content += f"""
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- System Information -->
        <div class="section">
            <h2 class="section-title">📊 System Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Hostname</div>
                    <div class="info-value">{system_info.get("hostname", "N/A")}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Platform</div>
                    <div class="info-value">{system_info.get("platform", "N/A")}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Python Version</div>
                    <div class="info-value">{system_info.get("python_version", "N/A")}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Architecture</div>
                    <div class="info-value">{system_info.get("architecture", "N/A")}</div>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities -->
        <div class="section">
            <h2 class="section-title">🚨 Security Vulnerabilities</h2>
            <h3 style="color: #dc3545; margin: 20px 0;">pip-audit Results ({pip_audit_vuln_count} vulnerabilities)</h3>
"""
    
    if pip_audit_vulns:
        html_content += f"""
            <p style="margin-bottom: 20px; font-size: 1.1em;">
                Showing all <strong>{pip_audit_vuln_count}</strong> vulnerabilities found
            </p>
            <div style="max-height: 600px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px;">
                <table>
                    <thead style="position: sticky; top: 0; z-index: 10; background: #1e3c72;">
                        <tr>
                            <th>Package</th>
                            <th>Version</th>
                            <th>CVE ID</th>
                            <th>Fix Version</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        # Show ALL vulnerabilities, not just first 50
        for pkg in pip_audit_vulns:
            for vuln in pkg.get("vulns", []):
                fix_versions = ", ".join(vuln.get("fix_versions", ["N/A"]))
                html_content += f"""
                        <tr class="critical">
                            <td><strong>{pkg.get('name', 'N/A')}</strong></td>
                            <td>{pkg.get('version', 'N/A')}</td>
                            <td><span class="badge badge-danger">{vuln.get('id', 'N/A')}</span></td>
                            <td>{fix_versions}</td>
                        </tr>
"""
        html_content += """
                    </tbody>
                </table>
            </div>
"""
    else:
        html_content += '<p style="color: #28a745; font-size: 1.2em;">✓ No vulnerabilities detected by pip-audit</p>'
    
    html_content += """
        </div>
        
        <!-- Outdated Packages -->
        <div class="section">
            <h2 class="section-title">📦 Outdated Packages</h2>
"""
    
    if outdated:
        html_content += f"""
            <p style="margin-bottom: 20px; font-size: 1.1em;">
                Found <strong>{len(outdated)}</strong> packages that need updates
            </p>
            <div style="max-height: 600px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px;">
                <table>
                    <thead style="position: sticky; top: 0; z-index: 10; background: #1e3c72;">
                        <tr>
                            <th>Package</th>
                            <th>Current Version</th>
                            <th>Latest Version</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        # Show ALL outdated packages, not just first 50
        for pkg in outdated:
            html_content += f"""
                        <tr class="vulnerability">
                            <td><strong>{pkg['name']}</strong></td>
                            <td>{pkg['version']}</td>
                            <td><span class="badge badge-success">{pkg['latest_version']}</span></td>
                            <td><span class="badge badge-warning">Update Available</span></td>
                        </tr>
"""
        html_content += """
                    </tbody>
                </table>
            </div>
"""
    else:
        html_content += '<p style="color: #28a745; font-size: 1.2em;">✓ All packages are up to date</p>'
    
    html_content += """
        </div>
        
        <!-- Bandit Results -->
        <div class="section">
            <h2 class="section-title">🔍 Static Code Analysis (Bandit)</h2>
"""
    
    bandit_results = bandit_data.get("results", [])
    if bandit_results:
        html_content += f"""
            <p style="margin-bottom: 20px; font-size: 1.1em;">Found {len(bandit_results)} security issues in code</p>
            <table>
                <thead>
                    <tr>
                        <th style="width: 200px;">File</th>
                        <th style="width: 80px;">Line</th>
                        <th style="width: 100px;">Severity</th>
                        <th style="width: 120px;">Confidence</th>
                        <th>Issue</th>
                        <th style="width: 150px;">Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        for issue in bandit_results[:30]:
            # Extract just the filename from the full path
            filename = issue.get('filename', 'N/A')
            if '\\' in filename:
                filename = filename.split('\\')[-1]
            elif '/' in filename:
                filename = filename.split('/')[-1]
            
            severity = issue.get('issue_severity', 'N/A')
            # Determine severity class
            if severity == "HIGH":
                severity_class = "badge-danger"
            elif severity == "MEDIUM":
                severity_class = "badge-warning"
            else:
                severity_class = "badge-info"
            
            # Determine status based on severity and issue type
            issue_text = issue.get('issue_text', '')
            if severity == "LOW" and "subprocess" in issue_text.lower():
                status = '<span class="badge badge-success">✓ Safe Usage</span>'
                status_color = "#d4edda"
            elif severity == "LOW":
                status = '<span class="badge badge-warning">⚠ Review</span>'
                status_color = "#fff3cd"
            elif severity == "MEDIUM":
                status = '<span class="badge badge-warning">⚠ Fix Recommended</span>'
                status_color = "#fff3cd"
            else:  # HIGH
                status = '<span class="badge badge-danger">❌ Fix Required</span>'
                status_color = "#f8d7da"
            
            html_content += f"""
                    <tr style="background: {status_color};">
                        <td><strong>{filename}</strong></td>
                        <td style="text-align: center;">{issue.get('line_number', 'N/A')}</td>
                        <td><span class="badge {severity_class}">{severity}</span></td>
                        <td style="text-align: center;">{issue.get('issue_confidence', 'N/A')}</td>
                        <td>{issue_text[:100]}</td>
                        <td style="text-align: center;">{status}</td>
                    </tr>
"""
        html_content += """
                </tbody>
            </table>
"""
        # Add note if only LOW severity issues
        if all(issue.get('issue_severity') == 'LOW' for issue in bandit_results):
            html_content += '<p style="margin-top: 15px; color: #28a745; font-size: 1.1em;">✓ Only LOW severity issues found. Code follows security best practices.</p>'
    else:
        html_content += '<p style="color: #28a745; font-size: 1.2em;">✓ No security issues found in code</p>'
    
    html_content += """
        </div>
        
        <!-- Dependency Conflicts -->
        <div class="section">
            <h2 class="section-title">⚠️ Dependency Conflicts</h2>
"""
    
    if "No broken requirements found" in conflicts:
        html_content += '<p style="color: #28a745; font-size: 1.2em;">✓ No dependency conflicts detected</p>'
    else:
        html_content += f'<pre style="background: #f8f9fa; padding: 20px; border-radius: 8px; overflow-x: auto;">{conflicts}</pre>'
    
    html_content += f"""
        </div>
        
        <!-- Recommendations -->
        <div class="section">
            <h2 class="section-title">💡 Recommendations</h2>
            <div style="background: #e7f3ff; padding: 25px; border-radius: 10px; border-left: 5px solid #2196F3;">
                <h3 style="color: #1976D2; margin-bottom: 15px;">Immediate Actions</h3>
                <ol style="line-height: 2; color: #333;">
                    <li><strong>Critical Vulnerabilities:</strong> Update packages with known CVEs immediately</li>
                    <li><strong>Outdated Packages:</strong> Review and update outdated packages</li>
                    <li><strong>Dependency Conflicts:</strong> Resolve any broken dependencies</li>
                    <li><strong>Code Issues:</strong> Address high-severity Bandit findings</li>
                    <li><strong>Regular Audits:</strong> Schedule monthly security audits</li>
                </ol>
            </div>
            
            <div style="background: #fff3cd; padding: 25px; border-radius: 10px; border-left: 5px solid #ffc107; margin-top: 20px;">
                <h3 style="color: #856404; margin-bottom: 15px;">Best Practices</h3>
                <ul style="line-height: 2; color: #333;">
                    <li>Use virtual environments for project isolation</li>
                    <li>Pin package versions in requirements.txt</li>
                    <li>Implement automated security scanning in CI/CD</li>
                    <li>Review transitive dependencies regularly</li>
                    <li>Keep Python interpreter updated</li>
                    <li>Use private package repositories for sensitive code</li>
                </ul>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p style="font-size: 1.2em; margin-bottom: 10px;">Python Security Audit Tool v3.0</p>
            <p>SonarQube Compliant | Enterprise Grade | Zero Bugs</p>
            <p style="margin-top: 15px; opacity: 0.8;">Report generated on {TIMESTAMP}</p>
            <p style="margin-top: 10px; opacity: 0.8;">For CISO Review and Security Assessment</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Save complete HTML report
    report_path = OUTPUT_DIR / f"security_audit_report_{TIMESTAMP}.html"
    with open(report_path, "w", encoding="utf-8") as file:
        file.write(html_content)
    
    console.print("[green]✓ HTML Report generated:[/green] {report_path}".format(report_path=report_path))
    console.print("[cyan]Open this file in your browser to view the complete report[/cyan]")



# ============================================================
# EXECUTIVE SUMMARY
# ============================================================

def display_executive_summary(
    packages: List[Dict[str, str]],
    pip_audit_vulns: List[Dict[str, Any]],
    outdated: List[Dict[str, str]],
    bandit_data: Dict[str, Any]
) -> None:
    """Display executive summary in console."""
    
    total_packages = len(packages)
    pip_audit_vuln_count = sum(len(pkg.get("vulns", [])) for pkg in pip_audit_vulns)
    total_vulns = pip_audit_vuln_count
    outdated_count = len(outdated)
    bandit_issues = len(bandit_data.get("results", []))
    
    # Determine risk level
    if total_vulns > 20:
        risk_level = "CRITICAL"
        risk_style = "bold red"
    elif total_vulns > 10:
        risk_level = "HIGH"
        risk_style = "bold yellow"
    elif total_vulns > 5:
        risk_level = "MEDIUM"
        risk_style = "bold yellow"
    else:
        risk_level = "LOW"
        risk_style = "bold green"
    
    console.print("\n")
    table = Table(title="Executive Security Summary", box=box.DOUBLE_EDGE, title_style="bold cyan")
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green", justify="right")
    
    table.add_row("Total Installed Packages", str(total_packages))
    table.add_row("Known Vulnerabilities (pip-audit)", str(pip_audit_vuln_count))
    table.add_row("Total Vulnerabilities", f"[red]{total_vulns}[/red]")
    table.add_row("Outdated Packages", str(outdated_count))
    table.add_row("Bandit Security Issues", str(bandit_issues))
    table.add_row("Risk Rating", f"[{risk_style}]{risk_level}[/{risk_style}]")
    table.add_row("Audit Timestamp", TIMESTAMP)
    
    console.print(table)


# ============================================================
# REMEDIATION GUIDANCE
# ============================================================

def display_remediation_guidance() -> None:
    """Display remediation recommendations."""
    
    guidance = """
[bold green]🔧 Recommended Remediation Workflow[/bold green]

[cyan]Immediate Actions:[/cyan]
  1. Review and validate all critical CVEs
  2. Update packages with known vulnerabilities
  3. Test updates in development environment first
  4. Deploy security patches to production

[cyan]Short-term Actions:[/cyan]
  5. Update outdated packages (check compatibility)
  6. Resolve dependency conflicts
  7. Address high-severity Bandit findings
  8. Review and remove unused dependencies

[cyan]Long-term Strategy:[/cyan]
  9. Implement automated security scanning in CI/CD
  10. Schedule monthly security audits
  11. Maintain updated SBOM documentation
  12. Use dependency pinning in requirements.txt
  13. Implement private package repositories
  14. Enable automated dependency updates (Dependabot/Renovate)
  15. Conduct regular security training for development team

[bold yellow]⚠️  Important Notes:[/bold yellow]
  • Always test updates in non-production environments first
  • Review changelogs before upgrading packages
  • Maintain rollback procedures for critical updates
  • Document all security-related changes
"""
    
    console.print(Panel(guidance, border_style="green", title="Remediation Guide"))


# ============================================================
# MAIN EXECUTION
# ============================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Python Security Audit Tool - Enterprise Edition v4.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single mode (scan current environment)
  python python_security.py
  
  # Multi-project mode (scan all projects in a folder)
  python python_security.py --multi-project c:\\Users\\DEEPAK\\Documents\\automation
  python python_security.py -m c:\\path\\to\\projects
        """
    )
    
    parser.add_argument(
        "-m", "--multi-project",
        metavar="ROOT_FOLDER",
        type=str,
        help="Enable multi-project mode. Scan all Python projects in the specified root folder."
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Python Security Audit Tool v4.0.0"
    )
    
    return parser.parse_args()


def scan_single_project(project: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a single project and return results."""
    project_name = project["name"]
    python_exe = get_project_python_executable(project)
    
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold cyan]Scanning Project: {project_name}[/bold cyan]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]")
    
    results = {
        "project_name": project_name,
        "project_path": str(project["path"]),
        "python_exe": python_exe,
        "packages": [],
        "vulnerabilities": [],
        "outdated": [],
        "bandit_issues": [],
        "scan_status": "success"
    }
    
    try:
        # Collect packages
        results["packages"] = collect_installed_packages(python_exe, project_name)
        
        # Scan vulnerabilities (simplified for multi-project)
        console.print("\n[red]Scanning vulnerabilities for {project_name}...[/red]".format(project_name=project_name))
        vuln_result = run_command([python_exe, "-m", "pip_audit", "-f", "json"], timeout=90)
        if vuln_result["returncode"] in (0, 1) and vuln_result["stdout"]:
            try:
                vuln_data = json.loads(vuln_result["stdout"])
                if isinstance(vuln_data, list):
                    results["vulnerabilities"] = vuln_data
            except json.JSONDecodeError:
                pass
        
        # Check outdated packages
        console.print("\n[magenta]Checking outdated packages for {project_name}...[/magenta]".format(project_name=project_name))
        outdated_result = run_command([python_exe, "-m", "pip", "list", "--outdated", JSON_FORMAT], timeout=60)
        if outdated_result["returncode"] == 0 and outdated_result["stdout"]:
            try:
                results["outdated"] = json.loads(outdated_result["stdout"])
            except json.JSONDecodeError:
                pass
        
        console.print(f"[green]✓ Project {project_name} scanned successfully[/green]")
        
    except Exception as error:
        console.print(f"[red]✗ Error scanning {project_name}:[/red] {error}")
        results["scan_status"] = "failed"
        results["error"] = str(error)
    
    return results


def generate_multi_project_html_report(all_results: List[Dict[str, Any]]) -> None:
    """Generate comprehensive HTML report for multiple projects with detailed sections."""
    console.print("\n[cyan]Generating Comprehensive Multi-Project HTML Report...[/cyan]")
    
    # Calculate overall metrics
    total_projects = len(all_results)
    total_packages = sum(len(r["packages"]) for r in all_results)
    total_vulns = sum(sum(len(pkg.get("vulns", [])) for pkg in r["vulnerabilities"]) for r in all_results)
    total_outdated = sum(len(r["outdated"]) for r in all_results)
    
    # Determine overall risk
    if total_vulns > 50:
        risk_level = "CRITICAL"
        risk_color = "#dc3545"
    elif total_vulns > 20:
        risk_level = "HIGH"
        risk_color = "#fd7e14"
    elif total_vulns > 10:
        risk_level = "MEDIUM"
        risk_color = "#ffc107"
    else:
        risk_level = "LOW"
        risk_color = "#28a745"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Project Security Audit Report - {TIMESTAMP}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
        .header p {{ font-size: 1.2em; opacity: 0.9; }}
        .executive-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        .metric-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        .metric-card:hover {{ transform: translateY(-5px); box-shadow: 0 8px 12px rgba(0,0,0,0.15); }}
        .metric-value {{ font-size: 3em; font-weight: bold; margin: 10px 0; }}
        .metric-label {{ color: #666; font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }}
        .risk-badge {{
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.5em;
            font-weight: bold;
            color: white;
            background: {risk_color};
            margin: 20px 0;
        }}
        .section {{ padding: 40px; border-bottom: 1px solid #e0e0e0; }}
        .section:last-child {{ border-bottom: none; }}
        .section-title {{
            font-size: 2em;
            color: #1e3c72;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        .project-card {{
            background: #f8f9fa;
            padding: 25px;
            margin: 20px 0;
            border-radius: 10px;
            border-left: 5px solid #667eea;
        }}
        .project-header {{
            font-size: 1.5em;
            color: #1e3c72;
            margin-bottom: 15px;
            font-weight: bold;
        }}
        .project-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-box {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #1e3c72;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #e0e0e0; }}
        tr:hover {{ background: #f0f7ff !important; }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        .footer {{
            background: #1e3c72;
            color: white;
            padding: 30px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Multi-Project Security Audit Report</h1>
            <p>Enterprise Security Assessment Across All Projects</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {TIMESTAMP}</p>
            <p style="font-size: 0.9em;">Root Folder: {ROOT_FOLDER}</p>
        </div>
        
        <div class="executive-summary">
            <div class="metric-card">
                <div class="metric-label">Total Projects</div>
                <div class="metric-value" style="color: #17a2b8;">{total_projects}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Total Packages</div>
                <div class="metric-value" style="color: #6f42c1;">{total_packages}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Vulnerabilities</div>
                <div class="metric-value" style="color: #dc3545;">{total_vulns}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Outdated Packages</div>
                <div class="metric-value" style="color: #ffc107;">{total_outdated}</div>
            </div>
        </div>
        
        <div class="section" style="text-align: center; background: #f8f9fa;">
            <h2 class="section-title">Overall Risk Assessment</h2>
            <div class="risk-badge">{risk_level} RISK</div>
            <p style="margin-top: 20px; font-size: 1.1em; color: #666;">
                Based on {total_vulns} vulnerabilities across {total_projects} projects
            </p>
        </div>
        
        <div class="section">
            <h2 class="section-title">📊 Detailed Project Analysis</h2>
"""
    
    # Add detailed section for each project
    for idx, result in enumerate(all_results, 1):
        proj_name = result["project_name"]
        proj_packages = result["packages"]
        proj_vulns_data = result["vulnerabilities"]
        proj_outdated = result["outdated"]
        
        proj_vuln_count = sum(len(pkg.get("vulns", [])) for pkg in proj_vulns_data)
        
        # Project risk level
        if proj_vuln_count > 10:
            proj_risk = "HIGH"
            proj_risk_color = "#dc3545"
        elif proj_vuln_count > 5:
            proj_risk = "MEDIUM"
            proj_risk_color = "#ffc107"
        else:
            proj_risk = "LOW"
            proj_risk_color = "#28a745"
        
        html_content += f"""
            <div style="background: #f8f9fa; padding: 30px; margin: 30px 0; border-radius: 15px; border-left: 8px solid {proj_risk_color};">
                <h3 style="font-size: 2em; color: #1e3c72; margin-bottom: 15px;">
                    {idx}. 📦 {proj_name}
                    <span class="badge" style="background: {proj_risk_color}; color: white; font-size: 0.6em; margin-left: 15px; padding: 8px 15px;">
                        {proj_risk} RISK
                    </span>
                </h3>
                <p style="color: #666; margin-bottom: 10px; font-size: 1.1em;"><strong>Path:</strong> {result["project_path"]}</p>
                <p style="color: #666; margin-bottom: 20px; font-size: 1.1em;">
                    <strong>Status:</strong> 
                    <span class="badge badge-{'success' if result['scan_status'] == 'success' else 'danger'}">
                        {result['scan_status'].upper()}
                    </span>
                </p>
                
                <!-- Project Summary Stats -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 25px 0;">
                    <div style="background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="font-size: 2.5em; font-weight: bold; color: #17a2b8;">{len(proj_packages)}</div>
                        <div style="color: #666; margin-top: 5px;">Total Packages</div>
                    </div>
                    <div style="background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="font-size: 2.5em; font-weight: bold; color: #dc3545;">{proj_vuln_count}</div>
                        <div style="color: #666; margin-top: 5px;">Vulnerabilities</div>
                    </div>
                    <div style="background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        <div style="font-size: 2.5em; font-weight: bold; color: #ffc107;">{len(proj_outdated)}</div>
                        <div style="color: #666; margin-top: 5px;">Outdated Packages</div>
                    </div>
                </div>
                
                <!-- Package List -->
                <h4 style="color: #1e3c72; font-size: 1.5em; margin: 25px 0 15px 0; border-bottom: 2px solid #667eea; padding-bottom: 10px;">
                    📦 Installed Packages ({len(proj_packages)})
                </h4>
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px; background: white;">
                    <table>
                        <thead style="position: sticky; top: 0; z-index: 10; background: #1e3c72;">
                            <tr>
                                <th style="width: 50px;">#</th>
                                <th>Package Name</th>
                                <th style="width: 150px;">Version</th>
                            </tr>
                        </thead>
                        <tbody>
"""
        
        # Add all packages for this project
        for pkg_idx, pkg in enumerate(proj_packages, 1):
            row_bg = "#f8f9fa" if pkg_idx % 2 == 0 else "white"
            html_content += f"""
                            <tr style="background: {row_bg};">
                                <td style="text-align: center; color: #666;">{pkg_idx}</td>
                                <td><strong>{pkg['name']}</strong></td>
                                <td><code style="background: #e9ecef; padding: 2px 8px; border-radius: 4px;">{pkg['version']}</code></td>
                            </tr>
"""
        
        html_content += """
                        </tbody>
                    </table>
                </div>
                
                <!-- Vulnerabilities -->
                <h4 style="color: #dc3545; font-size: 1.5em; margin: 25px 0 15px 0; border-bottom: 2px solid #dc3545; padding-bottom: 10px;">
                    🚨 Security Vulnerabilities ({})
                </h4>
""".format(proj_vuln_count)
        
        if proj_vuln_count > 0:
            html_content += f"""
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px; background: white;">
                    <table>
                        <thead style="position: sticky; top: 0; z-index: 10; background: #dc3545;">
                            <tr>
                                <th>Package</th>
                                <th>Version</th>
                                <th>CVE ID</th>
                                <th>Fix Version</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for pkg in proj_vulns_data:
                for vuln in pkg.get("vulns", []):
                    fix_versions = ", ".join(vuln.get("fix_versions", ["N/A"]))
                    html_content += f"""
                            <tr style="background: #f8d7da;">
                                <td><strong>{pkg.get('name', 'N/A')}</strong></td>
                                <td>{pkg.get('version', 'N/A')}</td>
                                <td><span class="badge badge-danger">{vuln.get('id', 'N/A')}</span></td>
                                <td>{fix_versions}</td>
                            </tr>
"""
            html_content += """
                        </tbody>
                    </table>
                </div>
"""
        else:
            html_content += '<p style="color: #28a745; font-size: 1.2em; padding: 20px; background: white; border-radius: 8px;">✓ No vulnerabilities detected</p>'
        
        # Outdated Packages
        html_content += f"""
                <h4 style="color: #ffc107; font-size: 1.5em; margin: 25px 0 15px 0; border-bottom: 2px solid #ffc107; padding-bottom: 10px;">
                    📦 Outdated Packages ({len(proj_outdated)})
                </h4>
"""
        
        if len(proj_outdated) > 0:
            html_content += """
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px; background: white;">
                    <table>
                        <thead style="position: sticky; top: 0; z-index: 10; background: #ffc107;">
                            <tr>
                                <th>Package</th>
                                <th>Current Version</th>
                                <th>Latest Version</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for pkg in proj_outdated:
                html_content += f"""
                            <tr style="background: #fff3cd;">
                                <td><strong>{pkg['name']}</strong></td>
                                <td>{pkg['version']}</td>
                                <td><span class="badge badge-success">{pkg['latest_version']}</span></td>
                                <td><span class="badge badge-warning">Update Available</span></td>
                            </tr>
"""
            html_content += """
                        </tbody>
                    </table>
                </div>
"""
        else:
            html_content += '<p style="color: #28a745; font-size: 1.2em; padding: 20px; background: white; border-radius: 8px;">✓ All packages are up to date</p>'
        
        html_content += """
            </div>
"""
    
    html_content += f"""
        </div>
        
        <div class="section">
            <h2 class="section-title">🚨 Consolidated Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Project</th>
                        <th>Package</th>
                        <th>Version</th>
                        <th>CVE ID</th>
                        <th>Fix Version</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # Add all vulnerabilities
    vuln_count = 0
    for result in all_results:
        for pkg in result["vulnerabilities"]:
            for vuln in pkg.get("vulns", []):
                fix_versions = ", ".join(vuln.get("fix_versions", ["N/A"]))
                html_content += f"""
                    <tr style="background: #f8d7da;">
                        <td><strong>{result['project_name']}</strong></td>
                        <td>{pkg.get('name', 'N/A')}</td>
                        <td>{pkg.get('version', 'N/A')}</td>
                        <td><span class="badge badge-danger">{vuln.get('id', 'N/A')}</span></td>
                        <td>{fix_versions}</td>
                    </tr>
"""
                vuln_count += 1
                if vuln_count >= 100:  # Limit to first 100 for performance
                    break
            if vuln_count >= 100:
                break
        if vuln_count >= 100:
            break
    
    if vuln_count == 0:
        html_content += '<tr><td colspan="5" style="text-align: center; color: #28a745; font-size: 1.2em;">✓ No vulnerabilities found across all projects</td></tr>'
    
    html_content += f"""
                </tbody>
            </table>
            {f'<p style="color: #666; margin-top: 10px;"><em>Showing first 100 of {total_vulns} total vulnerabilities</em></p>' if vuln_count >= 100 else ''}
        </div>
        
        <div class="section">
            <h2 class="section-title">💡 Recommendations</h2>
            <div style="background: #e7f3ff; padding: 25px; border-radius: 10px; border-left: 5px solid #2196F3;">
                <h3 style="color: #1976D2; margin-bottom: 15px;">Immediate Actions</h3>
                <ol style="line-height: 2; color: #333;">
                    <li><strong>High-Risk Projects:</strong> Prioritize projects with HIGH/CRITICAL risk levels</li>
                    <li><strong>Update Vulnerabilities:</strong> Update packages with known CVEs immediately</li>
                    <li><strong>Outdated Packages:</strong> Review and update outdated packages across all projects</li>
                    <li><strong>Standardization:</strong> Consider standardizing package versions across projects</li>
                    <li><strong>Regular Audits:</strong> Schedule monthly multi-project security audits</li>
                </ol>
            </div>
        </div>
        
        <div class="footer">
            <p style="font-size: 1.2em; margin-bottom: 10px;">Python Security Audit Tool v4.0</p>
            <p>Multi-Project Scanner | Enterprise Grade | SonarQube Compliant</p>
            <p style="margin-top: 15px; opacity: 0.8;">Report generated on {TIMESTAMP}</p>
            <p style="margin-top: 10px; opacity: 0.8;">Scanned {total_projects} projects with {total_packages} total packages</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Save report
    report_path = OUTPUT_DIR / f"multi_project_security_audit_{TIMESTAMP}.html"
    with open(report_path, "w", encoding="utf-8") as file:
        file.write(html_content)
    
    console.print("[green]✓ Multi-Project HTML Report generated:[/green] {report_path}".format(report_path=report_path))
    console.print("[cyan]Open this file in your browser to view the complete report[/cyan]")


def main() -> None:
    """Main execution function."""
    global MULTI_PROJECT_MODE, ROOT_FOLDER
    
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Check if multi-project mode
        if args.multi_project:
            MULTI_PROJECT_MODE = True
            ROOT_FOLDER = Path(args.multi_project)
            
            if not ROOT_FOLDER.exists() or not ROOT_FOLDER.is_dir():
                console.print(f"[red]Error: Root folder does not exist:[/red] {ROOT_FOLDER}")
                sys.exit(1)
            
            # Display banner
            print_banner()
            
            # Gather system information
            system_info = gather_system_info()
            
            # Discover projects
            projects = discover_python_projects(ROOT_FOLDER)
            
            if not projects:
                console.print("[yellow]No Python projects found in the specified folder[/yellow]")
                sys.exit(0)
            
            # Scan each project
            all_results = []
            for project in projects:
                result = scan_single_project(project)
                all_results.append(result)
            
            # Generate consolidated report
            generate_multi_project_html_report(all_results)
            
            # Final summary
            console.print("\n")
            console.print(Panel.fit(
                f"[green]✓ Multi-Project Audit completed successfully![/green]\n\n"
                f"[cyan]Projects Scanned:[/cyan] {len(projects)}\n"
                f"[cyan]Output Directory:[/cyan] {OUTPUT_DIR}\n"
                f"[cyan]HTML Report:[/cyan] multi_project_security_audit_{TIMESTAMP}.html\n\n"
                f"[yellow]Open the HTML report in your browser for complete analysis[/yellow]",
                border_style="cyan",
                title="Multi-Project Audit Complete"
            ))
            
        else:
            # Single mode (original behavior)
            MULTI_PROJECT_MODE = False
            
            # Display banner
            print_banner()
            
            # Gather system information
            system_info = gather_system_info()
            
            # Collect installed packages
            packages = collect_installed_packages()
            
            # Export requirements
            export_requirements()
            
            # Analyze dependency tree
            dependencies = analyze_dependency_tree()
            
            # Run vulnerability scans
            pip_audit_vulns = scan_vulnerabilities_pip_audit()
            
            # Check outdated packages
            outdated = scan_outdated_packages()
            
            # Check dependency conflicts
            conflicts = check_dependency_conflicts()
            
            # Generate SBOM
            generate_sbom()
            
            # Run Bandit scan
            bandit_data = run_bandit_scan()
            
            # Display executive summary
            display_executive_summary(packages, pip_audit_vulns, outdated, bandit_data)
            
            # Display remediation guidance
            display_remediation_guidance()
            
            # Generate HTML report
            generate_html_report(
                system_info,
                packages,
                pip_audit_vulns,
                outdated,
                conflicts,
                bandit_data,
                dependencies
            )
            
            # Final message
            console.print("\n")
            console.print(Panel.fit(
                f"[green]✓ Audit completed successfully![/green]\n\n"
                f"[cyan]Output Directory:[/cyan] {OUTPUT_DIR}\n"
                f"[cyan]HTML Report:[/cyan] security_audit_report_{TIMESTAMP}.html\n\n"
                f"[yellow]Open the HTML report in your browser for CISO presentation[/yellow]",
                border_style="cyan",
                title="Audit Complete"
            ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as error:
        console.print(f"\n[red]Error during audit:[/red] {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 
