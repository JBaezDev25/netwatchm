function Watch-NetWatchMLogs {
    <#
    .SYNOPSIS
        Watches journalctl output and raises a HIGH-severity alert
        when the exact uppercase keyword "HIGH" appears in a log line.

    .DESCRIPTION
        Read-only, non-destructive monitor. Uses journalctl --follow
        in a streaming pipeline. No system state is modified.
        Alert output goes to the PowerShell host only (Write-Host) plus
        an optional structured PSCustomObject on the success stream.

    .PARAMETER Unit
        The systemd unit to follow. Defaults to 'netwatchm'.

    .PARAMETER EmitObjects
        When set, each HIGH alert is also emitted as a PSCustomObject
        on the success stream so callers can pipe it further.

    .EXAMPLE
        Watch-NetWatchMLogs

    .EXAMPLE
        Watch-NetWatchMLogs -Unit netwatchm-web

    .EXAMPLE
        Watch-NetWatchMLogs -EmitObjects |
            Export-Csv -Path ~/high-alerts.csv -Append -NoTypeInformation

    .EXAMPLE
        Watch-NetWatchMLogs -EmitObjects |
            ConvertTo-Json | Out-File ~/high-alerts.jsonl -Append
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Unit = 'netwatchm',

        [Parameter()]
        [switch] $EmitObjects
    )

    # ── Validate journalctl is available (read-only check) ──────────────
    if (-not (Get-Command journalctl -ErrorAction SilentlyContinue)) {
        Write-Error "journalctl not found. This function requires a systemd-based Linux host."
        return
    }

    # ── Build read-only journalctl arguments ─────────────────────────────
    # --follow   : stream new entries as they arrive
    # --no-pager : suppress interactive pager
    # --output short-iso : include ISO timestamps in each line
    # No destructive flags: no --rotate, no --vacuum, no --flush
    [string[]] $jArgs = @(
        '--unit',    $Unit,
        '--follow',
        '--no-pager',
        '--output',  'short-iso'
    )

    Write-Host "[$([datetime]::Now.ToString('o'))] " -NoNewline -ForegroundColor DarkGray
    Write-Host "Watching journalctl -u $Unit  (Ctrl+C to stop)" -ForegroundColor Cyan

    # ── Stream and inspect each line ────────────────────────────────────
    try {
        & journalctl @jArgs | ForEach-Object {
            [string] $line = $_

            # Case-sensitive exact-word match for uppercase "HIGH"
            # [regex]::IsMatch without IgnoreCase — only fires on "HIGH", not "high"
            if ([regex]::IsMatch($line, '\bHIGH\b')) {

                [datetime]  $detected  = [datetime]::Now
                [string]    $timestamp = $detected.ToString('yyyy-MM-dd HH:mm:ss')

                # ── Console alert (non-destructive output only) ──────────
                Write-Host ""
                Write-Host "╔══════════════════════════════════════════════════╗" `
                    -ForegroundColor Red
                Write-Host "║  ⚠  HIGH-SEVERITY ALERT DETECTED                ║" `
                    -ForegroundColor Red
                Write-Host "╠══════════════════════════════════════════════════╣" `
                    -ForegroundColor Red
                Write-Host "║  Time   : $timestamp"                            -ForegroundColor Yellow
                Write-Host "║  Unit   : $Unit"                                 -ForegroundColor Yellow
                Write-Host "║  Source : journalctl (read-only stream)"         -ForegroundColor Yellow
                Write-Host "╠══════════════════════════════════════════════════╣" `
                    -ForegroundColor Red
                Write-Host "║  Log line:"                                       -ForegroundColor White
                Write-Host "║  $line"                                           -ForegroundColor White
                Write-Host "╚══════════════════════════════════════════════════╝" `
                    -ForegroundColor Red
                Write-Host ""

                # ── Structured object to success stream (pipeable) ────────
                if ($EmitObjects) {
                    [PSCustomObject] @{
                        Timestamp = $detected
                        Severity  = 'HIGH'
                        Unit      = $Unit
                        LogLine   = $line
                    }
                }
            }
        }
    }
    catch [System.OperationCanceledException] {
        Write-Host "`nWatch stopped by user." -ForegroundColor DarkGray
    }
    catch {
        Write-Error "Stream error: $_"
    }
}
