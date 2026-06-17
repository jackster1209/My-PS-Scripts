#Requires -Version 5.1
#Requires -Modules DnsServer

<#
.SYNOPSIS
    Reports on (and optionally converts to static) DNS A records whose host name
    matches one or more prefixes.

.DESCRIPTION
    Two operations in one script.

    REPORT (default)
        Enumerates A records whose host name starts with any supplied prefix and
        reports, per record:
            - Zone / HostName / FQDN
            - IP address
            - Dynamic vs Static (based on the aging timestamp)
            - Aging timestamp (dynamic records only)
            - Whether the IP currently answers an ICMP echo (ping)
            - Whether a PTR record exists for the IP
            - Whether the PTR host name matches the A record FQDN

        Output is plain objects, so pipe to Format-Table or Export-Csv as needed.

    CONVERT (-ConvertToStatic)
        Finds every *dynamic* A record matching the prefixes and converts it to a
        static record by clearing its aging timestamp (clone the record, null the
        Timestamp, Set-DnsServerResourceRecord). Honors -WhatIf / -Confirm and
        prompts per record by default (ConfirmImpact = High).

.PARAMETER Prefixes
    Comma-delimited list of host-name prefixes, e.g. "pre1, pre2, pre3".
    Matching is "starts with" and case-insensitive. Whitespace is trimmed.

.PARAMETER ZoneName
    One or more forward lookup zones to search. If omitted, all primary,
    non-auto-created forward zones on the server are searched.

.PARAMETER DnsServer
    DNS server to query / modify. Defaults to the local machine.

.PARAMETER ConvertToStatic
    When present, converts matching dynamic records to static instead of
    producing the report.

.PARAMETER PingTimeoutMs
    Per-host ICMP timeout in milliseconds (report mode). Default 1000.

.EXAMPLE
    .\Manage-PrefixedDnsRecords.ps1 -Prefixes "web, app, sql" | Format-Table -AutoSize

.EXAMPLE
    .\Manage-PrefixedDnsRecords.ps1 -Prefixes "web, app" -ZoneName corp.example.com |
        Export-Csv .\dns_report.csv -NoTypeInformation

.EXAMPLE
    # Preview the conversion without changing anything
    .\Manage-PrefixedDnsRecords.ps1 -Prefixes "web, app" -ConvertToStatic -WhatIf

.EXAMPLE
    # Convert without per-record prompts
    .\Manage-PrefixedDnsRecords.ps1 -Prefixes "web, app" -ConvertToStatic -Confirm:$false -DnsServer dc01
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string]$Prefixes,

    [string[]]$ZoneName,

    [string]$DnsServer = $env:COMPUTERNAME,

    [switch]$ConvertToStatic,

    [int]$PingTimeoutMs = 1000
)

#region Helpers ---------------------------------------------------------------

function ConvertTo-PrefixList {
    param([string]$Raw)
    $Raw -split ',' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' } |
        Select-Object -Unique
}

function Get-TargetZone {
    param([string[]]$ZoneName, [string]$DnsServer)

    if ($ZoneName) {
        foreach ($z in $ZoneName) {
            try {
                Get-DnsServerZone -Name $z -ComputerName $DnsServer -ErrorAction Stop
            }
            catch {
                Write-Warning "Zone '$z' not found on '$DnsServer': $($_.Exception.Message)"
            }
        }
    }
    else {
        Get-DnsServerZone -ComputerName $DnsServer |
            Where-Object {
                -not $_.IsReverseLookupZone -and
                $_.ZoneType -eq 'Primary' -and
                -not $_.IsAutoCreated
            }
    }
}

function Get-RecordFqdn {
    param([string]$HostName, [string]$ZoneName)
    if ($HostName -eq '@') { return $ZoneName }
    return ('{0}.{1}' -f $HostName, $ZoneName)
}

function Get-MatchingARecord {
    # Returns objects of { ZoneName, Record } for every A record matching a prefix.
    param([string[]]$Prefix, [object[]]$Zone, [string]$DnsServer)

    foreach ($z in $Zone) {
        $zn = $z.ZoneName
        try {
            $records = Get-DnsServerResourceRecord -ZoneName $zn -RRType A `
                -ComputerName $DnsServer -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not read records from '$zn': $($_.Exception.Message)"
            continue
        }

        foreach ($r in $records) {
            foreach ($p in $Prefix) {
                if ($r.HostName -like "$p*") {
                    [pscustomobject]@{ ZoneName = $zn; Record = $r }
                    break   # avoid emitting the same record twice if >1 prefix matches
                }
            }
        }
    }
}

function Test-IcmpResponse {
    param([string]$IPAddress, [int]$TimeoutMs)
    $ping = $null
    try {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        ($ping.Send($IPAddress, $TimeoutMs)).Status -eq 'Success'
    }
    catch { $false }
    finally { if ($ping) { $ping.Dispose() } }
}

function Get-PtrMatch {
    # Resolves the PTR for an IP and compares it to the expected A-record FQDN.
    param([string]$IPAddress, [string]$Fqdn, [string]$DnsServer)

    $result = [pscustomobject]@{ PtrExists = $false; PtrName = $null; PtrMatches = $false }

    try {
        $ptr = Resolve-DnsName -Name $IPAddress -Type PTR -Server $DnsServer -DnsOnly `
            -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' }
    }
    catch {
        return $result   # NXDOMAIN / no PTR
    }
    if (-not $ptr) { return $result }

    $names = @($ptr.NameHost)
    $target = $Fqdn.TrimEnd('.')

    $result.PtrExists  = $true
    $result.PtrName    = ($names -join ', ')
    $result.PtrMatches = [bool]($names | Where-Object { $_.TrimEnd('.') -ieq $target })
    $result
}

#endregion Helpers ------------------------------------------------------------

#region Report ----------------------------------------------------------------

function Invoke-DnsPrefixReport {
    param([object[]]$Found, [string]$DnsServer, [int]$PingTimeoutMs)

    foreach ($m in $Found) {
        $r        = $m.Record
        $zn       = $m.ZoneName
        $ip       = $r.RecordData.IPv4Address.IPAddressToString
        $fqdn     = Get-RecordFqdn -HostName $r.HostName -ZoneName $zn
        $dynamic  = ($null -ne $r.Timestamp)
        $ptr      = Get-PtrMatch -IPAddress $ip -Fqdn $fqdn -DnsServer $DnsServer

        [pscustomobject]@{
            Zone       = $zn
            HostName   = $r.HostName
            FQDN       = $fqdn
            IPAddress  = $ip
            RecordType = if ($dynamic) { 'Dynamic' } else { 'Static' }
            Timestamp  = if ($dynamic) { $r.Timestamp } else { $null }
            Responding = Test-IcmpResponse -IPAddress $ip -TimeoutMs $PingTimeoutMs
            PtrExists  = $ptr.PtrExists
            PtrName    = $ptr.PtrName
            PtrMatches = $ptr.PtrMatches
        }
    }
}

#endregion Report -------------------------------------------------------------

#region Convert ---------------------------------------------------------------

function Convert-DnsPrefixToStatic {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([object[]]$Found, [string]$DnsServer)

    foreach ($m in $Found) {
        $r  = $m.Record
        $zn = $m.ZoneName

        if ($null -eq $r.Timestamp) {
            Write-Verbose "Skipping '$($r.HostName)' in '$zn' - already static."
            continue
        }

        $ip     = $r.RecordData.IPv4Address.IPAddressToString
        $fqdn   = Get-RecordFqdn -HostName $r.HostName -ZoneName $zn
        $target = "$fqdn ($ip) in zone '$zn' on '$DnsServer'"

        if ($PSCmdlet.ShouldProcess($target, 'Convert dynamic A record to static')) {
            try {
                $new = $r.Clone()
                $new.Timestamp = $null            # clearing the timestamp makes it static
                Set-DnsServerResourceRecord -ZoneName $zn `
                    -OldInputObject $r -NewInputObject $new `
                    -ComputerName $DnsServer -ErrorAction Stop

                [pscustomobject]@{
                    FQDN = $fqdn; IPAddress = $ip; Zone = $zn; Result = 'Converted to static'
                }
            }
            catch {
                [pscustomobject]@{
                    FQDN = $fqdn; IPAddress = $ip; Zone = $zn
                    Result = "FAILED: $($_.Exception.Message)"
                }
            }
        }
    }
}

#endregion Convert ------------------------------------------------------------

#region Main ------------------------------------------------------------------

$prefixList = @(ConvertTo-PrefixList -Raw $Prefixes)
if (-not $prefixList) { throw "No valid prefixes parsed from '$Prefixes'." }
Write-Verbose ("Prefixes: {0}" -f ($prefixList -join ', '))

$zones = @(Get-TargetZone -ZoneName $ZoneName -DnsServer $DnsServer)
if (-not $zones) { throw "No matching forward lookup zones found on '$DnsServer'." }
Write-Verbose ("Searching {0} zone(s): {1}" -f $zones.Count, (($zones.ZoneName) -join ', '))

$found = @(Get-MatchingARecord -Prefix $prefixList -Zone $zones -DnsServer $DnsServer)
if (-not $found) {
    Write-Warning "No A records matched the supplied prefixes."
    return
}

if ($ConvertToStatic) {
    $dynamic = @($found | Where-Object { $null -ne $_.Record.Timestamp })
    if (-not $dynamic) {
        Write-Warning "No dynamic records to convert (all matches are already static)."
        return
    }
    Write-Verbose ("Converting {0} dynamic record(s) to static." -f $dynamic.Count)
    Convert-DnsPrefixToStatic -Found $dynamic -DnsServer $DnsServer
}
else {
    Invoke-DnsPrefixReport -Found $found -DnsServer $DnsServer -PingTimeoutMs $PingTimeoutMs
}

#endregion Main ---------------------------------------------------------------
