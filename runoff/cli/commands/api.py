"""BloodHound CE API commands."""

from __future__ import annotations

import click

from runoff.display import console
from runoff.display.tables import print_header, print_subheader, print_table


@click.command()
@click.option("--url", default="http://localhost:8080", help="BloodHound CE URL")
@click.pass_context
def auth(ctx, url):
    """Authenticate to BloodHound CE and store API token.

    Creates an API token interactively for file ingestion operations.

    Examples:
        runoff auth
        runoff auth --url http://bloodhound.local:8080
    """
    from runoff.api.config import APIConfig

    api_config = APIConfig()

    console.print("\n  [info][*] Create an API token in BloodHound CE:[/info]")
    console.print("    Administration > API Tokens > Create Token")
    console.print()

    try:
        token_id = click.prompt("  Token ID", type=str).strip()
        token_key = click.prompt("  Token Key", type=str, hide_input=True).strip()
    except (EOFError, KeyboardInterrupt, click.Abort):
        console.print("\n[text.dim]Cancelled[/text.dim]")
        return

    if not token_id or not token_key:
        console.print("[error]Token ID and Key are required[/error]")
        return

    console.print(f"\n  [info][*] Testing connection to {url}...[/info]")

    try:
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI(url, token_id, token_key)
        if api.test_connection():
            user_info = api.get_self()
            user_name = user_info.get("data", {}).get("name", "Unknown")
            console.print("  [success][+] Authentication successful![/success]")
            console.print(f"    User: {user_name}")

            api_config.save(url=url, token_id=token_id, token_key=token_key)
            console.print("  [success][+] Credentials saved[/success]")
        else:
            console.print("[error]Authentication failed[/error]")
    except Exception as e:
        console.print(f"[error]API error: {e}[/error]")


@click.group(invoke_without_command=True)
@click.pass_context
def ingest(ctx):
    """Ingest files into BloodHound CE or view history.

    Subcommands:
        files      Upload JSON/ZIP files
        history    Show file ingest history
    """
    if ctx.invoked_subcommand is None:
        console.print("  [header]Usage:[/header] runoff ingest [text.dim]COMMAND [ARGS][/text.dim]")
        console.print()
        console.print("  [subheader]Subcommands:[/subheader]")
        console.print(
            "    [info]files[/info] [text.secondary]FILE...[/text.secondary]    Upload JSON/ZIP files"
        )
        console.print("    [info]history[/info]            Show file ingest history")
        console.print()
        console.print("  [subheader]Examples:[/subheader]")
        console.print("    [text.dim]runoff ingest files *.zip[/text.dim]")
        console.print("    [text.dim]runoff ingest files data.json users.json[/text.dim]")
        console.print("    [text.dim]runoff ingest history[/text.dim]")
        console.print()


@ingest.command("files")
@click.argument("file_list", nargs=-1, required=True)
@click.option("--no-wait", is_flag=True, help="Don't wait for completion")
@click.pass_context
def ingest_files(ctx, file_list, no_wait):
    """Upload JSON/ZIP files to BloodHound CE.

    Examples:
        runoff ingest files *.zip
        runoff ingest files bloodhound_data.json computers.json
    """
    from runoff.api.config import APIConfig

    api_config = APIConfig()

    if not api_config.has_credentials():
        console.print("[error]No API credentials. Run 'runoff auth' first.[/error]")
        return

    try:
        url, token_id, token_key = api_config.get_credentials()
    except Exception as e:
        console.print(f"[error]Failed to get API credentials: {e}[/error]")
        return

    # Expand file patterns
    from runoff.api.ingest import expand_file_patterns

    files = expand_file_patterns(list(file_list))

    if not files:
        console.print("[error]No matching files found[/error]")
        return

    console.print(f"  [info][*] Found {len(files)} file(s) to upload[/info]")
    for f in files[:5]:
        console.print(f"    - {f}")
    if len(files) > 5:
        console.print(f"    ... and {len(files) - 5} more")

    try:
        from runoff.api.client import BloodHoundAPI
        from runoff.api.ingest import format_bytes
        from runoff.api.ingest import ingest_files as do_ingest

        api = BloodHoundAPI(url, token_id, token_key)

        def progress(filename, current, total):
            console.print(f"  Uploading ({current}/{total}): {filename}")

        result = do_ingest(
            api, files, wait_for_completion=not no_wait, timeout=300, progress_callback=progress
        )

        console.print("  [success][+] Upload complete![/success]")
        console.print(f"    Files: {result['files_uploaded']}")
        console.print(f"    Size: {format_bytes(result['total_bytes'])}")

        if not no_wait and result.get("ingestion_complete"):
            console.print("  [success][+] Ingestion complete[/success]")

    except KeyboardInterrupt:
        console.print("\n[text.dim]Upload interrupted[/text.dim]")
    except Exception as e:
        console.print(f"[error]Upload failed: {e}[/error]")


@ingest.command("history")
@click.pass_context
def ingest_history(ctx):
    """Show file ingest history."""
    from runoff.api.config import APIConfig

    api_config = APIConfig()

    if not api_config.has_credentials():
        console.print("[error]No API credentials. Run 'runoff auth' first.[/error]")
        return

    try:
        url, token_id, token_key = api_config.get_credentials()
    except Exception as e:
        console.print(f"[error]Failed to get API credentials: {e}[/error]")
        return

    try:
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI(url, token_id, token_key)
        result = api.get_file_upload_jobs()
        jobs = result.get("data", [])

        if not jobs:
            console.print("[text.dim]No ingest history found[/text.dim]")
            return

        print_header("Ingest History")
        print_subheader(f"Found {len(jobs)} job(s)")

        # Status code mapping
        status_map = {
            0: "Pending",
            1: "Running",
            2: "Complete",
            3: "Failed",
            6: "Ingesting",
        }

        rows = []
        for job in jobs[:20]:
            status_code = job.get("status", -1)
            status = status_map.get(status_code, f"Unknown ({status_code})")
            job_id = str(job.get("id", ""))[:8]
            rows.append([job_id, status, job.get("start_time", "-"), job.get("end_time", "-")])

        print_table(["Job ID", "Status", "Start", "End"], rows)

    except Exception as e:
        console.print(f"[error]API error: {e}[/error]")
