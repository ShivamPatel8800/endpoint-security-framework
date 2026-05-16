"""
Command Line Interface for ESF
"""

import click
import json
import sys
from pathlib import Path

@click.group()
@click.option('--config', '-c', default='/etc/esf/config.yaml', help='Path to config file')
@click.pass_context
def cli(ctx, config):
    """Endpoint Security Framework - Proactive Linux Security Hardening"""
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config

@cli.command()
@click.pass_context
def status(ctx):
    """Show framework status and recent alerts."""
    from .main import ESFOrchestrator
    esf = ESFOrchestrator(ctx.obj['config_path'])
    
    click.echo(click.style("=== ESF Status ===", fg="blue", bold=True))
    sys_info = esf.get_system_info()
    click.echo(f"Host: {sys_info['hostname']} | OS: {sys_info['os_name']} | Kernel: {sys_info['kernel_version']}")
    
    baseline_stats = esf.file_integrity.get_baseline_stats() if esf.file_integrity else {"total_files": 0}
    click.echo(f"File Baseline: {baseline_stats.get('total_files', 0)} files monitored")
    
    alerts = esf.logger.get_alerts(limit=5) if esf.logger else []
    click.echo(click.style(f"\nRecent Alerts ({len(alerts)}):", fg="yellow"))
    for alert in alerts:
        color = "red" if alert.severity in ["critical", "high"] else "yellow"
        click.echo(click.style(f"  [{alert.severity.upper()}] {alert.title}", fg=color))

@cli.command()
@click.option('--continuous', is_flag=True, help='Run continuously as a daemon')
@click.pass_context
def monitor(ctx, continuous):
    """Start real-time monitoring."""
    from .main import ESFOrchestrator
    esf = ESFOrchestrator(ctx.obj['config_path'])
    
    if continuous:
        click.echo("Starting continuous monitoring... Press Ctrl+C to stop.")
        esf.start_all()
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            click.echo("\nShutting down...")
            esf.stop_all()
    else:
        click.echo("Running single scan cycle...")
        esf.run_single_cycle()

@cli.command()
@click.pass_context
def scan(ctx):
    """Run a full security scan."""
    from .main import ESFOrchestrator
    esf = ESFOrchestrator(ctx.obj['config_path'])
    
    click.echo(click.style("Starting Full Security Scan...", fg="blue", bold=True))
    
    click.echo("1. Checking Process Anomalies...")
    proc_alerts = esf.process_monitor.scan_once()
    click.echo(f"   Found {len(proc_alerts)} process anomalies.")
    
    click.echo("2. Checking File Integrity...")
    int_alerts = esf.file_integrity.check_integrity()
    click.echo(f"   Found {len(int_alerts)} integrity violations.")
    
    click.echo("3. Checking Service Hardening...")
    hardening = esf.service_hardener.run_all_checks()
    click.echo(f"   SSH Non-Compliant: {len(hardening.get('ssh', {}).get('non_compliant', []))}")
    
    click.echo(click.style("Scan Complete.", fg="green"))

@cli.command()
@click.argument('action', type=click.Choice(['create', 'verify']))
@click.option('--file', '-f', help='Verify specific file')
@click.pass_context
def baseline(ctx, action, file):
    """Create or verify file baseline."""
    from .main import ESFOrchestrator
    esf = ESFOrchestrator(ctx.obj['config_path'])
    
    if action == 'create':
        click.echo("Creating baseline (this may take a few minutes)...")
        with click.progressbar(length=100, label='Scanning') as bar:
            # Simplified progress simulation
            stats = esf.file_integrity.create_baseline()
            bar.update(100)
        click.echo(click.style(f"Success! {stats['files_added']} files baselined.", fg="green"))
        
    elif action == 'verify':
        if file:
            result = esf.file_integrity.verify_file(file)
            click.echo(json.dumps(result, indent=2))
        else:
            alerts = esf.file_integrity.check_integrity()
            if not alerts:
                click.echo(click.style("All files match baseline.", fg="green"))
            else:
                click.echo(click.style(f"{len(alerts)} discrepancies found!", fg="red"))

@cli.command()
@click.pass_context
def threats(ctx):
    """List detected threats and remediation history."""
    from .main import ESFOrchestrator
    esf = ESFOrchestrator(ctx.obj['config_path'])
    
    alerts = esf.logger.get_alerts(limit=20) if esf.logger else []
    click.echo(click.style("=== Recent Threats ===", fg="red", bold=True))
    
    if not alerts:
        click.echo("No threats detected.")
        return
        
    for a in alerts:
        click.echo(f"- [{a.severity}] {a.category}: {a.title}")

if __name__ == '__main__':
    cli()
