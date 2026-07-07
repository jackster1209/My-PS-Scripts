<#
.SYNOPSIS
    Fetches the WSUS SusClientId and recent Windows Update warnings/errors from
    every enabled Windows Server that logged on to the domain within a window.

.DESCRIPTION
    Queries AD for Server-OS computers active in the last N days (default 45),
    then over a single WinRM session per server:
      * reads HKLM\...\WindowsUpdate\SusClientId
      * pulls recent Windows Update warnings/errors (Level 1/2/3) from one or
        more event log sources (see -EventSource)
    Outputs two files (same base name):
      * .csv  -> Name, SusClientId, Duplicate, Status, LastLogon, OS
      * .log  -> per-server block of the recent Windows Update warnings/errors
    Any SusClientId shared by more than one server is flagged Duplicate = True.

.PARAMETER EventSource
    One or more event log sources to collect from. Accepts friendly aliases or
    raw "LogName" / "LogName::ProviderName" specs. Non-existent logs on a given
    server are reported as unavailable rather than failing the run.
      System       -> System log, Microsoft-Windows-WindowsUpdateClient provider
                      (classic scan/download/install/reboot results)
      Operational  -> Microsoft-Windows-WindowsUpdateClient/Operational channel
      <custom>     -> e.g. 'Microsoft-Windows-UpdateOrchestrator/Operational'
                      or 'System::Some-Other-Provider'
    Default: System

.REQUIREMENTS
    - PowerShell 7+ (ForEach-Object -Parallel, Test-Connection -TargetName)
    - RSAT ActiveDirectory module
    - WinRM enabled on targets + local admin rights on them

.EXAMPLE
    .\Get-SusClientIdReport.ps1
    .\Get-SusClientIdReport.ps1 -EventSource System,Operational -EventCount 15
    .\Get-SusClientIdReport.ps1 -EventSource 'Microsoft-Windows-UpdateOrchestrator/Operational'
#>

#Requires -Version 7.0
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [int]$DaysSinceLogon   = 45,
    [int]$EventCount       = 10,
    [string[]]$EventSource = @('System'),
    [string]$OutputPath    = ".\SusClientId-Report_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv",
    [int]$ThrottleLimit    = 32,
    [switch]$SkipPing
)

Import-Module ActiveDirectory -ErrorAction Stop

# Resolve friendly aliases / raw specs into { LogName; Provider; Label } objects
function Resolve-EventSource {
    param([string[]]$Sources)
    switch -Regex ($Sources) {
        '^System$'      { [pscustomobject]@{ LogName = 'System'; Provider = 'Microsoft-Windows-WindowsUpdateClient'; Label = 'System/WUClient' } }
        '^Operational$' { [pscustomobject]@{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Provider = $null; Label = 'WUClient/Operational' } }
        default {
            $parts = $_ -split '::', 2
            [pscustomobject]@{
                LogName  = $parts[0]
                Provider = $(if ($parts.Count -eq 2 -and $parts[1]) { $parts[1] } else { $null })
                Label    = $_
            }
        }
    }
}
$SourceSpecs = @(Resolve-EventSource -Sources $EventSource)

$cutoffFileTime = (Get-Date).AddDays(-$DaysSinceLogon).ToFileTime()

Write-Host "Querying AD for enabled Windows Servers active in the last $DaysSinceLogon days..." -ForegroundColor Cyan
$servers = Get-ADComputer -Filter "OperatingSystem -like '*Server*' -and Enabled -eq 'True' -and LastLogonTimeStamp -ge $cutoffFileTime" `
    -Properties OperatingSystem, LastLogonTimeStamp, DNSHostName |
    Select-Object Name, DNSHostName, OperatingSystem,
        @{ N = 'LastLogon'; E = { [datetime]::FromFileTime($_.LastLogonTimeStamp) } }

Write-Host "Found $($servers.Count) server(s). Sources: $($SourceSpecs.Label -join ', '). Fetching SusClientId + last $EventCount warnings/errors per source over WinRM..." -ForegroundColor Cyan

$results = $servers | ForEach-Object -Parallel {
    $skipPing   = $using:SkipPing
    $eventCount = $using:EventCount
    $sources    = $using:SourceSpecs
    $target     = if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name }

    $row = [ordered]@{
        Name        = $_.Name
        SusClientId = $null
        Duplicate   = $false
        Status      = $null
        LastLogon   = $_.LastLogon
        OS          = $_.OperatingSystem
        Events      = @()
    }

    if (-not $skipPing -and -not (Test-Connection -TargetName $target -Count 1 -Quiet)) {
        $row.Status = 'Unreachable (ping)'
        return [PSCustomObject]$row
    }

    try {
        $remote = Invoke-Command -ComputerName $target -ErrorAction Stop -ArgumentList $eventCount, $sources -ScriptBlock {
            param([int]$Count, [object[]]$Sources)

            $out = [ordered]@{ SusClientId = $null; Events = @() }

            # SusClientId
            try {
                $out.SusClientId = (Get-ItemProperty `
                    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate' `
                    -Name SusClientId -ErrorAction Stop).SusClientId
            } catch { }

            # Recent WU warnings/errors from each requested source (rendered here)
            # Level: 1=Critical, 2=Error, 3=Warning
            $collected = foreach ($src in $Sources) {
                $filter = @{ LogName = $src.LogName; Level = 1, 2, 3 }
                if ($src.Provider) { $filter.ProviderName = $src.Provider }
                try {
                    Get-WinEvent -FilterHashtable $filter -MaxEvents $Count -ErrorAction Stop | ForEach-Object {
                        [pscustomobject]@{
                            Time = $_.TimeCreated
                            Line = '{0:yyyy-MM-dd HH:mm:ss}  [{1,-11}]  {2,-22}  ID {3,-5}  {4}' -f `
                                $_.TimeCreated, $_.LevelDisplayName, $src.Label, $_.Id, (($_.Message -replace '\s+', ' ').Trim())
                        }
                    }
                } catch {
                    [pscustomobject]@{
                        Time = [datetime]::MinValue
                        Line = '({0}: no warnings/errors, or log unavailable: {1})' -f $src.Label, ($_.Exception.Message -replace '\s+', ' ')
                    }
                }
            }

            # Merge sources, newest first; placeholders (MinValue) sink to the bottom
            $out.Events = @($collected | Sort-Object Time -Descending | Select-Object -ExpandProperty Line)
            [PSCustomObject]$out
        }

        $row.SusClientId = $remote.SusClientId
        $row.Events      = $remote.Events
        $row.Status      = if ($remote.SusClientId) { 'OK' } else { 'No SusClientId value' }
    }
    catch {
        $row.Status = "Error: $($_.Exception.Message -replace '\s+', ' ')"
    }

    [PSCustomObject]$row
} -ThrottleLimit $ThrottleLimit

# Flag SusClientIds that appear on more than one server
$dupIds = $results | Where-Object SusClientId |
    Group-Object SusClientId | Where-Object Count -gt 1 |
    Select-Object -ExpandProperty Name

foreach ($r in $results) {
    if ($r.SusClientId -and $dupIds -contains $r.SusClientId) { $r.Duplicate = $true }
}

# --- CSV output ---
$results | Sort-Object SusClientId, Name |
    Select-Object Name, SusClientId, Duplicate, Status, LastLogon, OS |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --- Event .log output ---
$logPath  = [System.IO.Path]::ChangeExtension($OutputPath, '.log')
$logLines = [System.Collections.Generic.List[string]]::new()
$logLines.Add("Windows Update Event Report")
$logLines.Add("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$logLines.Add("Servers   : $($results.Count)   (last $EventCount warnings/errors per source)")
$logLines.Add("Sources   : $($SourceSpecs.Label -join ', ')")
$logLines.Add('=' * 100)

foreach ($r in ($results | Sort-Object Name)) {
    $logLines.Add('')
    $logLines.Add('#' * 100)
    $logLines.Add("SERVER: $($r.Name)    SusClientId: $($r.SusClientId)    Status: $($r.Status)")
    $logLines.Add('#' * 100)
    if ($r.Events -and $r.Events.Count) {
        foreach ($line in $r.Events) { $logLines.Add($line) }
    } else {
        $logLines.Add('  (no warnings/errors - clean)')
    }
}
$logLines | Set-Content -Path $logPath -Encoding UTF8

# --- Summary ---
$ok     = ($results | Where-Object Status -eq 'OK').Count
$failed = ($results | Where-Object { $_.Status -ne 'OK' }).Count
Write-Host "`nDone. $($results.Count) processed  |  $ok OK  |  $failed failed/unreachable" -ForegroundColor Green
Write-Host "CSV : $OutputPath"
Write-Host "Log : $logPath"

if ($dupIds) {
    $dupCount = ($results | Where-Object Duplicate).Count
    Write-Warning "$($dupIds.Count) duplicate SusClientId value(s) across $dupCount server(s) -- these are your likely offenders:"
    $results | Where-Object Duplicate | Sort-Object SusClientId, Name |
        Format-Table Name, SusClientId, LastLogon -AutoSize
}
else {
    Write-Host "No duplicate SusClientIds detected." -ForegroundColor Green
}
