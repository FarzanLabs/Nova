from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nova.modules.domain import scan_domain
from nova.modules.httpintel import scan_url
from nova.modules.ip import scan_ip
from nova.modules.username import search_username


VERSION = "1.0.0"
REPORT_DIR = Path("reports")

app = typer.Typer(
    name="nova",
    help="Nova — passive cybersecurity OSINT toolkit.",
    no_args_is_help=True,
    add_completion=True,
)

console = Console()


# ============================================================
# UI
# ============================================================

def banner() -> None:
    console.print(
        Panel.fit(
            "[bold]NOVA[/bold]\n"
            "[dim]Passive Cybersecurity OSINT Toolkit[/dim]\n"
            f"[dim]v{VERSION}[/dim]",
            border_style="bright_blue",
        )
    )


def section(title: str) -> None:
    console.print()
    console.rule(f"[bold cyan]{title}[/bold cyan]")


def error(message: str) -> None:
    console.print(
        Panel(
            f"[red]{message}[/red]",
            title="Error",
            border_style="red",
        )
    )


def info(message: str) -> None:
    console.print(f"[cyan]•[/cyan] {message}")


def success(message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


# ============================================================
# GENERAL HELPERS
# ============================================================

def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_filename(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "_", value)
    return value.strip("_")[:100] or "target"


def save_json(result, name: str) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    target = safe_filename(str(result.target))
    path = REPORT_DIR / f"{name}_{target}.json"

    data = result.to_dict()
    data["meta"] = {
        "tool": "Nova",
        "version": VERSION,
        "generated_at": timestamp(),
    }

    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    return path


def print_findings(result) -> None:
    if not result.findings:
        console.print(
            Panel(
                "[yellow]No findings returned.[/yellow]",
                border_style="yellow",
            )
        )
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
    )

    table.add_column(
        "Category",
        style="cyan",
        no_wrap=True,
    )
    table.add_column(
        "Key",
        style="white",
        no_wrap=True,
    )
    table.add_column(
        "Value",
        style="green",
    )
    table.add_column(
        "Source",
        style="dim",
        no_wrap=True,
    )

    for finding in result.findings:
        value = str(finding.value)

        if len(value) > 180:
            value = value[:177] + "..."

        table.add_row(
            finding.category,
            finding.key,
            value,
            finding.source,
        )

    console.print(table)


def show_summary(result) -> None:
    section("SCAN SUMMARY")

    categories: dict[str, int] = {}

    for finding in result.findings:
        categories[finding.category] = (
            categories.get(finding.category, 0) + 1
        )

    table = Table(box=box.SIMPLE)

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Target", str(result.target))
    table.add_row("Total findings", str(len(result.findings)))
    table.add_row("Categories", str(len(categories)))

    for category, count in sorted(categories.items()):
        table.add_row(category, str(count))

    console.print(table)


def show_result(
    result,
    *,
    save: bool = False,
    report_name: str = "scan",
) -> None:
    section(f"RESULTS — {result.target}")

    print_findings(result)
    show_summary(result)

    if save:
        path = save_json(result, report_name)
        success(f"JSON report saved to {path}")


# ============================================================
# TARGET DETECTION
# ============================================================

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_email(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            value.strip(),
        )
    )


def is_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme.lower() in {"http", "https"}


def is_domain(value: str) -> bool:
    value = value.strip().lower()

    if "/" in value or "@" in value:
        return False

    return bool(
        re.fullmatch(
            r"(?:[a-z0-9-]+\.)+[a-z]{2,63}",
            value,
        )
    )


def detect_target(target: str) -> str:
    target = target.strip()

    if is_email(target):
        return "email"

    if is_url(target):
        return "url"

    if is_ip(target):
        return "ip"

    if is_domain(target):
        return "domain"

    return "username"


# ============================================================
# EMAIL ENGINE
# ============================================================

def email_scan(email_address: str) -> list[dict[str, str]]:
    email_address = email_address.strip().lower()
    domain_name = email_address.split("@", 1)[1]

    findings: list[dict[str, str]] = []

    def add(
        category: str,
        key: str,
        value,
        source: str,
    ) -> None:
        if value is None:
            return

        value = str(value).strip()

        if not value:
            return

        findings.append(
            {
                "category": category,
                "key": key,
                "value": value,
                "source": source,
            }
        )

    add("TARGET", "email", email_address, "Nova")
    add("EMAIL", "domain", domain_name, "Nova")

    try:
        answers = dns.resolver.resolve(
            domain_name,
            "MX",
            lifetime=5,
        )

        for answer in answers:
            add(
                "EMAIL",
                "mx",
                answer.to_text().rstrip("."),
                "DNS",
            )
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(
            domain_name,
            "TXT",
            lifetime=5,
        )

        for answer in answers:
            value = answer.to_text()

            if "v=spf1" in value.lower():
                add(
                    "EMAIL",
                    "spf",
                    value,
                    "DNS",
                )
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(
            f"_dmarc.{domain_name}",
            "TXT",
            lifetime=5,
        )

        for answer in answers:
            value = answer.to_text()

            if "v=dmarc1" in value.lower():
                add(
                    "EMAIL",
                    "dmarc",
                    value,
                    "DNS",
                )
    except Exception:
        pass

    return findings


def run_email(
    email_address: str,
    save: bool = False,
) -> None:
    findings = email_scan(email_address)

    section(
        f"EMAIL INTELLIGENCE — {email_address}"
    )

    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
    )

    table.add_column("Category", style="cyan")
    table.add_column("Key", style="white")
    table.add_column("Value", style="green")
    table.add_column("Source", style="dim")

    for item in findings:
        table.add_row(
            item["category"],
            item["key"],
            item["value"],
            item["source"],
        )

    console.print(table)

    if save:
        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            REPORT_DIR
            / f"email_{safe_filename(email_address)}.json"
        )

        payload = {
            "target": email_address,
            "type": "email",
            "meta": {
                "tool": "Nova",
                "version": VERSION,
                "generated_at": timestamp(),
            },
            "findings": findings,
        }

        path.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        success(
            f"JSON report saved to {path}"
        )


# ============================================================
# URL ENGINE
# ============================================================

def run_url(
    target: str,
    save: bool = False,
) -> None:
    target = target.strip()

    if not is_url(target):
        if "://" not in target:
            target = "https://" + target

    info(f"Inspecting {target}")

    data = scan_url(target)

    section("HTTP INTELLIGENCE")

    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
    )

    table.add_column(
        "Property",
        style="cyan",
    )

    table.add_column(
        "Value",
        style="green",
    )

    rows = [
        ("URL", getattr(data, "url", None)),
        ("Final URL", getattr(data, "final_url", None)),
        ("Status", getattr(data, "status_code", None)),
        ("Server", getattr(data, "server", None)),
        ("Powered By", getattr(data, "powered_by", None)),
        ("Content Type", getattr(data, "content_type", None)),
        ("Content Length", getattr(data, "content_length", None)),
        ("Title", getattr(data, "title", None)),
    ]

    for key, value in rows:
        if value is not None:
            table.add_row(
                key,
                str(value),
            )

    console.print(table)

    technologies = getattr(
        data,
        "technologies",
        None,
    )

    if technologies:
        console.print(
            Panel(
                "\n".join(
                    f"• {tech}"
                    for tech in technologies
                ),
                title="Technologies",
                border_style="cyan",
            )
        )

    security_headers = getattr(
        data,
        "security_headers",
        None,
    )

    if security_headers:
        console.print(
            Panel(
                "\n".join(
                    f"{key}: {value}"
                    for key, value in security_headers.items()
                ),
                title="Security Headers",
                border_style="green",
            )
        )

    redirects = getattr(
        data,
        "redirects",
        None,
    )

    if redirects:
        console.print(
            Panel(
                "\n".join(
                    str(item)
                    for item in redirects
                ),
                title="Redirect Chain",
                border_style="yellow",
            )
        )

    if save:
        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            REPORT_DIR
            / f"url_{safe_filename(target)}.json"
        )

        payload = {
            "target": target,
            "type": "url",
            "meta": {
                "tool": "Nova",
                "version": VERSION,
                "generated_at": timestamp(),
            },
            "result": {
                "url": getattr(data, "url", None),
                "final_url": getattr(data, "final_url", None),
                "status_code": getattr(data, "status_code", None),
                "server": getattr(data, "server", None),
                "powered_by": getattr(data, "powered_by", None),
                "content_type": getattr(data, "content_type", None),
                "content_length": getattr(data, "content_length", None),
                "title": getattr(data, "title", None),
                "technologies": technologies,
                "security_headers": security_headers,
                "redirects": redirects,
            },
        }

        path.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )

        success(
            f"JSON report saved to {path}"
        )


# ============================================================
# DOMAIN ENGINE
# ============================================================

def run_domain(
    target: str,
    save: bool = False,
) -> None:
    target = target.strip()

    if not is_domain(target):
        error("Invalid domain format.")
        raise typer.Exit(code=1)

    info(f"Investigating {target}")

    result = scan_domain(target)

    show_result(
        result,
        save=save,
        report_name="domain",
    )


# ============================================================
# IP ENGINE
# ============================================================

def run_ip(
    target: str,
    save: bool = False,
) -> None:
    target = target.strip()

    if not is_ip(target):
        error("Invalid IP address.")
        raise typer.Exit(code=1)

    info(f"Investigating {target}")

    result = scan_ip(target)

    show_result(
        result,
        save=save,
        report_name="ip",
    )


# ============================================================
# USERNAME ENGINE
# ============================================================

def run_username(
    target: str,
    save: bool = False,
) -> None:
    target = target.strip().lstrip("@")

    if not target:
        error("Username cannot be empty.")
        raise typer.Exit(code=1)

    info(
        f"Searching public sources for @{target}"
    )

    profiles = search_username(target)

    section(
        f"USERNAME INTELLIGENCE — @{target}"
    )

    table = Table(
        box=box.SIMPLE_HEAVY,
        expand=True,
    )

    table.add_column(
        "Platform",
        style="cyan",
    )

    table.add_column(
        "Status",
        style="green",
    )

    table.add_column(
        "Username",
        style="white",
    )

    table.add_column(
        "URL",
        style="blue",
    )

    for profile in profiles:
        status = (
            "[green]FOUND[/green]"
            if profile.found
            else "[dim]NOT FOUND[/dim]"
        )

        table.add_row(
            profile.platform,
            status,
            profile.username,
            profile.url,
        )

    console.print(table)

    found = [
        profile
        for profile in profiles
        if profile.found
    ]

    success(
        f"{len(found)} public profile(s) found."
    )

    if save:
        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        path = (
            REPORT_DIR
            / f"username_{safe_filename(target)}.json"
        )

        payload = {
            "target": target,
            "type": "username",
            "meta": {
                "tool": "Nova",
                "version": VERSION,
                "generated_at": timestamp(),
            },
            "profiles": [
                {
                    "platform": profile.platform,
                    "username": profile.username,
                    "url": profile.url,
                    "found": profile.found,
                    "status": profile.status,
                    "name": profile.name,
                    "bio": profile.bio,
                    "location": profile.location,
                    "website": profile.website,
                    "avatar": profile.avatar,
                }
                for profile in profiles
            ],
        }

        path.write_text(
            json.dumps(
                payload,
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            encoding="utf-8",
        )

        success(
            f"JSON report saved to {path}"
        )


# ============================================================
# METADATA
# ============================================================

def run_metadata(file: Path) -> None:
    section(
        f"FILE METADATA — {file.name}"
    )

    stat = file.stat()

    table = Table(
        box=box.SIMPLE_HEAVY,
    )

    table.add_column(
        "Property",
        style="cyan",
    )

    table.add_column(
        "Value",
        style="green",
    )

    table.add_row(
        "Name",
        file.name,
    )

    table.add_row(
        "Path",
        str(file.resolve()),
    )

    table.add_row(
        "Size",
        f"{stat.st_size:,} bytes",
    )

    table.add_row(
        "Suffix",
        file.suffix or "None",
    )

    table.add_row(
        "Modified",
        datetime.fromtimestamp(
            stat.st_mtime
        ).isoformat(),
    )

    console.print(table)


# ============================================================
# COMMANDS
# ============================================================

@app.command()
def url(
    target: str = typer.Argument(
        ...,
        help="HTTP/HTTPS URL.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save results as JSON.",
    ),
):
    """Inspect a URL using passive HTTP intelligence."""
    banner()
    run_url(target, save)


@app.command()
def domain(
    target: str = typer.Argument(
        ...,
        help="Domain to investigate.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save results as JSON.",
    ),
):
    """Perform passive domain intelligence."""
    banner()
    run_domain(target, save)


@app.command()
def ip(
    target: str = typer.Argument(
        ...,
        help="IPv4 or IPv6 address.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save results as JSON.",
    ),
):
    """
    Investigate an IP using RDAP, ASN, DNS
    and multi-source geolocation.
    """
    banner()
    run_ip(target, save)


@app.command()
def username(
    target: str = typer.Argument(
        ...,
        help="Username to search.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save results as JSON.",
    ),
):
    """Search public platforms for a username."""
    banner()
    run_username(target, save)


@app.command()
def email(
    target: str = typer.Argument(
        ...,
        help="Email address.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save results as JSON.",
    ),
):
    """Analyze email-domain infrastructure."""
    banner()

    if not is_email(target):
        error("Invalid email address.")
        raise typer.Exit(code=1)

    info(f"Investigating {target}")
    run_email(target, save)


@app.command()
def metadata(
    file: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Local file to inspect.",
    ),
):
    """Inspect local file metadata."""
    banner()
    run_metadata(file)


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Automatically identify and investigate a target.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Save results as JSON.",
    ),
):
    """
    Automatically identify a target and
    select the appropriate engine.
    """
    banner()

    target = target.strip()

    if not target:
        error("Target cannot be empty.")
        raise typer.Exit(code=1)

    target_type = detect_target(target)

    section("TARGET IDENTIFICATION")

    table = Table(box=box.SIMPLE)

    table.add_column(
        "Target",
        style="cyan",
    )

    table.add_column(
        "Detected Type",
        style="green",
    )

    table.add_row(
        target,
        target_type.upper(),
    )

    console.print(table)

    if target_type == "email":
        run_email(target, save)

    elif target_type == "url":
        run_url(target, save)

    elif target_type == "ip":
        run_ip(target, save)

    elif target_type == "domain":
        run_domain(target, save)

    else:
        run_username(target, save)


# ============================================================
# GLOBAL OPTIONS
# ============================================================

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show Nova version and exit.",
    ),
):
    """
    Nova — passive cybersecurity OSINT toolkit.
    """

    if version:
        console.print(f"Nova {VERSION}")
        raise typer.Exit(code=0)

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()

