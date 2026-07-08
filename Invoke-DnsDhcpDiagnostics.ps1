#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only DNS/DHCP diagnostics and reporting toolkit for Windows Server
    AD-integrated DNS and Microsoft DHCP.

.DESCRIPTION
    Gathers raw inventory/config data from DNS and DHCP servers, runs the
    pass/warn/fail test catalog against it (design doc section 5.1-5.3),
    and renders both a console summary and CSV exports. DDNS tandem
    analysis (section 5.4) is not yet implemented — see
    dns-dhcp-diagnostics-design.md sections 4 and 9 for the full roadmap.
    This script never writes to DNS/DHCP.
#>
[CmdletBinding()]
param(
    [string[]] $DnsServer,
    [string[]] $DhcpServer,
    [string[]] $Zone,
    [string[]] $Scope,
    [switch] $IncludeReverseZones,
    [ValidateSet('Dns', 'Dhcp', 'Ddns', 'All')]
    [string[]] $Tests = @('All'),
    [ValidateSet('Report', 'Export', 'Both')]
    [string] $Mode = 'Both',
    [string] $OutputPath = ".\DnsDhcpReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch] $RawDump,
    [int] $StaleThresholdDays,
    [switch] $FullOwnershipScan,
    [pscredential] $Credential,
    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'
$script:LogFilePath = $null
$script:OwnershipSampleSize = 200

#region Shared Helpers

function Write-DiagLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO'
    )

    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Verbose $line
    if ($script:LogFilePath) {
        Add-Content -Path $script:LogFilePath -Value $line
    }
}

function New-DiagResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('DNS', 'DHCP', 'DDNS')] [string] $Category,
        [Parameter(Mandatory)] [string] $TestName,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Error')] [string] $Status,
        [Parameter(Mandatory)] [string] $Finding,
        [string] $Detail = '',
        $Data = $null
    )

    [PSCustomObject]@{
        Category  = $Category
        TestName  = $TestName
        Target    = $Target
        Status    = $Status
        Finding   = $Finding
        Detail    = $Detail
        Data      = $Data
        Timestamp = Get-Date
    }
}

function ConvertTo-SafeFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)

    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [System.Text.RegularExpressions.Regex]::Escape($invalid)
    [System.Text.RegularExpressions.Regex]::Replace($Name, $pattern, '_')
}

function ConvertTo-UInt32FromIp {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Net.IPAddress] $IPAddress)

    $bytes = $IPAddress.GetAddressBytes()
    ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
}

function ConvertFrom-PtrRecordToIp {
    # Reconstructs a dotted IPv4 address from a PTR record's relative host
    # name plus its in-addr.arpa zone name (e.g. HostName '5' in zone
    # '10.38.10.in-addr.arpa' -> '10.38.10.5'). Returns $null for anything
    # that isn't a plain /24-style in-addr.arpa zone (ip6.arpa, delegated
    # sub-octet zones, etc.) rather than guessing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] [string] $HostName
    )

    if ($ZoneName -notmatch '\.in-addr\.arpa$' -or $HostName -notmatch '^\d+$') { return $null }
    $zoneLabels = ($ZoneName -replace '\.in-addr\.arpa$', '') -split '\.'
    if ($zoneLabels.Count -ne 3) { return $null }
    [array]::Reverse($zoneLabels)
    ($zoneLabels + $HostName) -join '.'
}

function Invoke-Analyzer {
    # Runs one analyzer call and folds its output (single result or array)
    # into $ResultList, converting an unexpected analyzer exception into an
    # Error row instead of aborting the run — same never-terminate contract
    # collectors already follow.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.Generic.List[object]] $ResultList,
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $TestName,
        [Parameter(Mandatory)] [string] $Target
    )

    try {
        @(& $ScriptBlock) | ForEach-Object { if ($_) { $ResultList.Add($_) } }
    }
    catch {
        $ResultList.Add((New-DiagResult -Category $Category -TestName $TestName -Target $Target `
                    -Status 'Error' -Finding "Analyzer failed: $($_.Exception.Message)"))
    }
}

function Add-CollectedRow {
    # Appends rows into the shared $Collected buckets used for raw CSV export.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Collected,
        [Parameter(Mandatory)] [string] $Bucket,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows
    )

    if (-not $Collected.ContainsKey($Bucket)) {
        $Collected[$Bucket] = [System.Collections.Generic.List[object]]::new()
    }
    foreach ($row in $Rows) {
        if ($null -ne $row) { $Collected[$Bucket].Add($row) }
    }
}

#endregion Shared Helpers

#region Bootstrap

function Test-RequiredModule {
    [CmdletBinding()]
    param()

    $requiredModules = 'DnsServer', 'DhcpServer'
    $missing = @($requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })

    if ($missing.Count -gt 0) {
        Write-Host ''
        Write-Host "Required PowerShell module(s) not found: $($missing -join ', ')" -ForegroundColor Red
        Write-Host 'Install the RSAT feature(s) for the missing module(s) and re-run:' -ForegroundColor Yellow
        if ($missing -contains 'DnsServer') {
            Write-Host '  Windows Server : Install-WindowsFeature RSAT-DNS-Server'
            Write-Host '  Windows 10/11  : Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0'
        }
        if ($missing -contains 'DhcpServer') {
            Write-Host '  Windows Server : Install-WindowsFeature RSAT-DHCP'
            Write-Host '  Windows 10/11  : Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0'
        }
        Write-Host ''
        throw "Missing required module(s): $($missing -join ', '). See guidance above."
    }

    foreach ($moduleName in $requiredModules) {
        Import-Module -Name $moduleName -ErrorAction Stop
    }

    Write-DiagLog "Required modules present: $($requiredModules -join ', ')"
}

function Resolve-TargetServers {
    [CmdletBinding()]
    param(
        [string[]] $DnsServer,
        [string[]] $DhcpServer,
        [pscredential] $Credential
    )

    $resolvedDns = $DnsServer
    $resolvedDhcp = $DhcpServer

    if (-not $resolvedDns) {
        Write-DiagLog 'No -DnsServer specified; discovering domain controllers via AD.'
        try {
            $adParams = @{ Filter = '*'; ErrorAction = 'Stop' }
            if ($Credential) { $adParams['Credential'] = $Credential }
            $resolvedDns = @((Get-ADDomainController @adParams).HostName)
        }
        catch {
            Write-DiagLog "AD domain controller discovery failed: $($_.Exception.Message)" 'WARN'
            $resolvedDns = @()
        }
    }

    if (-not $resolvedDhcp) {
        Write-DiagLog 'No -DhcpServer specified; discovering authorized DHCP servers via Get-DhcpServerInDC.'
        try {
            $resolvedDhcp = @((Get-DhcpServerInDC -ErrorAction Stop).DnsName)
        }
        catch {
            Write-DiagLog "DHCP server discovery failed: $($_.Exception.Message)" 'WARN'
            $resolvedDhcp = @()
        }
    }

    [PSCustomObject]@{
        DnsServers  = $resolvedDns
        DhcpServers = $resolvedDhcp
    }
}

function Test-ServerConnectivity {
    # Lightweight reachability pre-flight. Unreachable servers become Error
    # result rows instead of throwing, so one dead host never aborts the run.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $ComputerName,
        [Parameter(Mandatory)] [ValidateSet('DNS', 'DHCP')] [string] $Category
    )

    foreach ($computer in $ComputerName) {
        $reachable = $false
        try {
            $reachable = [bool](Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction Stop)
        }
        catch {
            $reachable = $false
        }

        if ($reachable) {
            New-DiagResult -Category $Category -TestName 'Server Reachability' -Target $computer `
                -Status 'Pass' -Finding "$computer is reachable."
        }
        else {
            New-DiagResult -Category $Category -TestName 'Server Reachability' -Target $computer `
                -Status 'Error' -Finding "$computer did not respond to connectivity probe." `
                -Detail 'Skipping collection for this server.'
        }
    }
}

function New-DiagCimSession {
    # Only needed when -Credential is supplied; the *Server cmdlets accept
    # -CimSession so alternate credentials can flow through without PSRemoting.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $ComputerName,
        [Parameter(Mandatory)] [pscredential] $Credential
    )

    $sessions = @{}
    foreach ($computer in $ComputerName) {
        try {
            $sessions[$computer] = New-CimSession -ComputerName $computer -Credential $Credential -ErrorAction Stop
        }
        catch {
            Write-DiagLog "Failed to create CIM session to $computer : $($_.Exception.Message)" 'WARN'
        }
    }
    $sessions
}

#endregion Bootstrap

#region Collectors
# Pure data-gathering: no pass/warn/fail analysis here (that's Phase 2/3).
# Every collector is try/catch-wrapped internally and returns plain data
# objects; callers add Error rows to the results stream on failure.

function Get-DnsInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }

    $zones = @(Get-DnsServerZone @cimParam | Select-Object @{n = 'DnsServer'; e = { $ComputerName } },
        ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, IsReverseLookupZone, IsAutoCreated)

    $forwarders = Get-DnsServerForwarder @cimParam -ErrorAction SilentlyContinue
    $rootHints = @(Get-DnsServerRootHint @cimParam -ErrorAction SilentlyContinue)
    $recursion = Get-DnsServerRecursion @cimParam -ErrorAction SilentlyContinue
    $scavenging = Get-DnsServerScavenging @cimParam -ErrorAction SilentlyContinue
    $listening = Get-DnsServerSetting @cimParam -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ListeningIPAddress -ErrorAction SilentlyContinue

    $nicIPs = @()
    try {
        $nicIPs = @(Get-CimInstance -ComputerName $ComputerName -ClassName Win32_NetworkAdapterConfiguration `
                -Filter 'IPEnabled=True' -ErrorAction Stop | Select-Object -ExpandProperty IPAddress |
                Where-Object { $_ -match '\.' })
    }
    catch {
        Write-DiagLog "Get-DnsInventory: could not enumerate NIC IPs on $ComputerName : $($_.Exception.Message)" 'WARN'
    }

    $serviceState = $null
    try {
        $serviceState = (Get-Service -ComputerName $ComputerName -Name DNS -ErrorAction Stop).Status
    }
    catch {
        Write-DiagLog "Get-DnsInventory: could not query DNS service state on $ComputerName : $($_.Exception.Message)" 'WARN'
    }

    [PSCustomObject]@{
        DnsServer        = $ComputerName
        ServiceState     = $serviceState
        Zones            = $zones
        Forwarders       = @($forwarders.IPAddress)
        RootHintCount    = $rootHints.Count
        RecursionEnabled = $recursion.Enable
        ScavengingEnabled = $scavenging.ScavengingState
        ScavengingInterval = $scavenging.ScavengingInterval
        LastScavengeTime = $scavenging.LastScavengeTime
        ListeningIPs     = @($listening)
        NicIPs           = $nicIPs
    }
}

function Get-DnsZoneDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }

    $soa = Get-DnsServerResourceRecord @cimParam -ZoneName $ZoneName -RRType Soa -ErrorAction SilentlyContinue
    $ns = @(Get-DnsServerResourceRecord @cimParam -ZoneName $ZoneName -RRType Ns -ErrorAction SilentlyContinue)
    $aging = Get-DnsServerZoneAging @cimParam -Name $ZoneName -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        DnsServer          = $ComputerName
        ZoneName           = $ZoneName
        SoaSerial          = $soa.RecordData.SerialNumber
        SoaPrimaryServer   = $soa.RecordData.PrimaryServer
        NameServers        = @($ns.RecordData.NameServer)
        AgingEnabled       = $aging.AgingEnabled
        NoRefreshInterval  = $aging.NoRefreshInterval
        RefreshInterval    = $aging.RefreshInterval
        ScavengeServers    = $aging.ScavengeServers
    }
}

function Get-DnsRecordDump {
    # Collected once per zone; feeds both the raw CSV dump and any later
    # analyzers so the zone is never re-enumerated per-test.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }

    Get-DnsServerResourceRecord @cimParam -ZoneName $ZoneName -ErrorAction Stop |
        Select-Object @{n = 'DnsServer'; e = { $ComputerName } }, @{n = 'ZoneName'; e = { $ZoneName } },
            HostName, RecordType, Timestamp, TimeToLive,
            @{n = 'IsStatic'; e = { -not $_.Timestamp } },
            @{n = 'RecordData'; e = { $_.RecordData.ToString() } }
}

function Get-DhcpInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }

    $settings = Get-DhcpServerSetting @cimParam -ErrorAction SilentlyContinue
    $auditLog = Get-DhcpServerAuditLog @cimParam -ErrorAction SilentlyContinue

    $authorized = $false
    try {
        $authorized = [bool](Get-DhcpServerInDC -ErrorAction Stop | Where-Object {
                $_.DnsName -eq $ComputerName -or $_.IPAddress.IPAddressToString -eq $ComputerName
            })
    }
    catch {
        Write-DiagLog "Get-DhcpInventory: authorization cross-check failed for $ComputerName : $($_.Exception.Message)" 'WARN'
    }

    $serviceState = $null
    try {
        $serviceState = (Get-Service -ComputerName $ComputerName -Name DHCPServer -ErrorAction Stop).Status
    }
    catch {
        Write-DiagLog "Get-DhcpInventory: could not query DHCPServer service state on $ComputerName : $($_.Exception.Message)" 'WARN'
    }

    [PSCustomObject]@{
        DhcpServer        = $ComputerName
        ServiceState      = $serviceState
        IsAuthorized      = $authorized
        AuditLogEnabled   = $settings.ActivatePolicies
        AuditLogPath      = $auditLog.Path
        AuditLogDiskCheck = $auditLog.DiskCheckInterval
    }
}

function Get-DhcpScopeDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ScopeId,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }

    $scope = Get-DhcpServerv4Scope @cimParam -ScopeId $ScopeId -ErrorAction Stop
    $stats = Get-DhcpServerv4ScopeStatistics @cimParam -ScopeId $ScopeId -ErrorAction SilentlyContinue
    $options = @(Get-DhcpServerv4OptionValue @cimParam -ScopeId $ScopeId -ErrorAction SilentlyContinue)
    $failover = Get-DhcpServerv4Failover @cimParam -ScopeId $ScopeId -ErrorAction SilentlyContinue
    $exclusions = @(Get-DhcpServerv4ExclusionRange @cimParam -ScopeId $ScopeId -ErrorAction SilentlyContinue)

    [PSCustomObject]@{
        DhcpServer          = $ComputerName
        ScopeId             = $ScopeId
        Name                = $scope.Name
        State               = $scope.State
        StartRange          = $scope.StartRange
        EndRange            = $scope.EndRange
        SubnetMask          = $scope.SubnetMask
        LeaseDuration       = $scope.LeaseDuration
        ConflictDetectionAttempts = $scope.ConflictDetectionAttempts
        PercentageInUse     = $stats.PercentageInUse
        AddressesFree       = $stats.Free
        AddressesInUse      = $stats.InUse
        Options             = $options
        ExclusionRanges     = $exclusions
        FailoverRelationship = $failover.Name
        FailoverMode        = $failover.Mode
        FailoverPartner     = $failover.PartnerServer
        FailoverState       = $failover.State
    }
}

function Get-DhcpLeaseDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ScopeId,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }

    $leases = Get-DhcpServerv4Lease @cimParam -ScopeId $ScopeId -ErrorAction Stop |
        Select-Object @{n = 'DhcpServer'; e = { $ComputerName } }, @{n = 'ScopeId'; e = { $ScopeId } },
            IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime,
            @{n = 'Type'; e = { 'Lease' } }

    $reservations = Get-DhcpServerv4Reservation @cimParam -ScopeId $ScopeId -ErrorAction SilentlyContinue |
        Select-Object @{n = 'DhcpServer'; e = { $ComputerName } }, @{n = 'ScopeId'; e = { $ScopeId } },
            IPAddress, ClientId, @{n = 'HostName'; e = { $_.Name } }, @{n = 'AddressState'; e = { 'Reservation' } },
            @{n = 'LeaseExpiryTime'; e = { $null } }, @{n = 'Type'; e = { 'Reservation' } }

    @($leases) + @($reservations)
}

function Get-DdnsConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [string] $ScopeId,
        [Microsoft.Management.Infrastructure.CimSession] $CimSession
    )

    $cimParam = if ($CimSession) { @{ CimSession = $CimSession } } else { @{ ComputerName = $ComputerName } }
    $scopeParam = if ($ScopeId) { @{ ScopeId = $ScopeId } } else { @{} }

    $dnsSetting = Get-DhcpServerv4DnsSetting @cimParam @scopeParam -ErrorAction SilentlyContinue
    $credential = $null
    $proxyMembers = @()

    if (-not $ScopeId) {
        # Server-level-only lookups; avoid repeating per scope.
        $credential = Get-DhcpServerDnsCredential @cimParam -ErrorAction SilentlyContinue
        try {
            $proxyMembers = @(Get-ADGroupMember -Identity 'DnsUpdateProxy' -ErrorAction Stop | Select-Object -ExpandProperty Name)
        }
        catch {
            Write-DiagLog "Get-DdnsConfiguration: could not read DnsUpdateProxy membership: $($_.Exception.Message)" 'WARN'
        }
    }

    [PSCustomObject]@{
        DhcpServer               = $ComputerName
        ScopeId                  = $ScopeId
        DynamicUpdates           = $dnsSetting.DynamicUpdates
        DeleteDnsRROnLeaseExpiry = $dnsSetting.DeleteDnsRROnLeaseExpiry
        UpdateDnsRRForOlderClients = $dnsSetting.UpdateDnsRRForOlderClients
        NameProtection           = $dnsSetting.NameProtection
        DnsCredentialConfigured  = [bool]$credential
        DnsCredentialUserName    = $credential.UserName
        DnsUpdateProxyMembers    = $proxyMembers
    }
}

function Get-RecordOwnership {
    # Samples records from a zone and reads the AD object owner off the
    # record's ACL. AD-integrated DNS zones live under either the
    # DomainDnsZones or ForestDnsZones application partition depending on
    # ReplicationScope, so both are tried before giving up on a record.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [string] $ReplicationScope = 'Domain',
        [switch] $FullScan
    )

    $records = @(Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop |
            Where-Object { $_.Timestamp })

    if (-not $FullScan -and $records.Count -gt $script:OwnershipSampleSize) {
        $records = $records | Get-Random -Count $script:OwnershipSampleSize
    }

    try {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
        $partitionCandidates = @(
            "DC=$ZoneName,CN=MicrosoftDNS,DC=DomainDnsZones,$($rootDse.defaultNamingContext)",
            "DC=$ZoneName,CN=MicrosoftDNS,DC=ForestDnsZones,$($rootDse.rootDomainNamingContext)"
        )
    }
    catch {
        Write-DiagLog "Get-RecordOwnership: could not read RootDSE for owner lookups: $($_.Exception.Message)" 'WARN'
        return @()
    }

    foreach ($record in $records) {
        $owner = $null
        foreach ($searchBase in $partitionCandidates) {
            try {
                $adObject = Get-ADObject -SearchBase $searchBase -Filter "Name -eq '$($record.HostName)'" `
                    -Properties nTSecurityDescriptor -ErrorAction Stop | Select-Object -First 1
                if ($adObject) {
                    $owner = $adObject.nTSecurityDescriptor.Owner
                    break
                }
            }
            catch {
                continue
            }
        }

        [PSCustomObject]@{
            DnsServer  = $ComputerName
            ZoneName   = $ZoneName
            HostName   = $record.HostName
            RecordType = $record.RecordType
            Owner      = $owner
        }
    }
}

#endregion Collectors

#region Analyzers
# Take collector output (already gathered in Main's Stage 1), return
# New-DiagResult objects. No data access here — analyzers only make live
# probes when the probe itself IS the test (e.g. "does this forwarder
# answer"), never to re-fetch config that a collector already gathered.

# --- DNS server-level (design 5.1) ---

function Test-DnsServiceHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $Inventory
    )

    if ($Inventory.ServiceState -eq 'Running') {
        New-DiagResult -Category 'DNS' -TestName 'Service Health' -Target $ComputerName `
            -Status 'Pass' -Finding 'DNS Server service is running.'
    }
    elseif ($null -eq $Inventory.ServiceState) {
        New-DiagResult -Category 'DNS' -TestName 'Service Health' -Target $ComputerName `
            -Status 'Error' -Finding 'Could not determine DNS Server service state.'
    }
    else {
        New-DiagResult -Category 'DNS' -TestName 'Service Health' -Target $ComputerName `
            -Status 'Fail' -Finding "DNS Server service is $($Inventory.ServiceState), not Running."
    }
}

function Test-DnsResponsiveness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $Inventory
    )

    $probeZone = $Inventory.Zones | Where-Object { -not $_.IsReverseLookupZone -and -not $_.IsAutoCreated } | Select-Object -First 1
    if (-not $probeZone) {
        return New-DiagResult -Category 'DNS' -TestName 'Responsiveness' -Target $ComputerName `
            -Status 'Info' -Finding 'No forward zone available to probe.'
    }

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Resolve-DnsName -Server $ComputerName -Name $probeZone.ZoneName -Type SOA -QuickTimeout -ErrorAction Stop
        $null = Resolve-DnsName -Server $ComputerName -Name $probeZone.ZoneName -Type A -QuickTimeout -ErrorAction SilentlyContinue
        $sw.Stop()
        $elapsedMs = $sw.ElapsedMilliseconds

        $status = if ($elapsedMs -gt 2000) { 'Warn' } else { 'Pass' }
        New-DiagResult -Category 'DNS' -TestName 'Responsiveness' -Target $ComputerName `
            -Status $status -Finding "Responded to SOA query for $($probeZone.ZoneName) in ${elapsedMs}ms." `
            -Data ([PSCustomObject]@{ ZoneProbed = $probeZone.ZoneName; ElapsedMs = $elapsedMs })
    }
    catch {
        New-DiagResult -Category 'DNS' -TestName 'Responsiveness' -Target $ComputerName `
            -Status 'Fail' -Finding "No response probing $($probeZone.ZoneName): $($_.Exception.Message)"
    }
}

function Test-DnsForwarders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $Inventory
    )

    $results = [System.Collections.Generic.List[object]]::new()

    if (-not $Inventory.Forwarders -and $Inventory.RootHintCount -eq 0) {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Forwarders & Root Hints' -Target $ComputerName `
                -Status 'Warn' -Finding 'No forwarders and no root hints configured; server cannot resolve outside its own zones.'))
        return $results
    }

    foreach ($forwarder in $Inventory.Forwarders) {
        try {
            $null = Resolve-DnsName -Server $forwarder -Name '.' -Type NS -QuickTimeout -ErrorAction Stop
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Forwarders & Root Hints' -Target "$ComputerName -> $forwarder" `
                    -Status 'Pass' -Finding "Forwarder $forwarder is answering."))
        }
        catch {
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Forwarders & Root Hints' -Target "$ComputerName -> $forwarder" `
                    -Status 'Fail' -Finding "Forwarder $forwarder did not answer: $($_.Exception.Message)"))
        }
    }

    if (-not $Inventory.Forwarders) {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Forwarders & Root Hints' -Target $ComputerName `
                -Status 'Info' -Finding "No forwarders configured; relying on $($Inventory.RootHintCount) root hints."))
    }

    $results
}

function Test-DnsRecursionScavenging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $Inventory
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $results.Add((New-DiagResult -Category 'DNS' -TestName 'Recursion Configuration' -Target $ComputerName `
            -Status 'Info' -Finding "Recursion is $(if ($Inventory.RecursionEnabled) { 'enabled' } else { 'disabled' })."))

    if (-not $Inventory.ScavengingEnabled) {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Server Scavenging' -Target $ComputerName `
                -Status 'Info' -Finding 'Server-level scavenging is disabled.'))
        return $results
    }

    $interval = $Inventory.ScavengingInterval
    $lastScavenge = $Inventory.LastScavengeTime

    if (-not $lastScavenge -or $lastScavenge -eq [datetime]::MinValue) {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Server Scavenging' -Target $ComputerName `
                -Status 'Warn' -Finding 'Scavenging is enabled but has never run.'))
    }
    elseif ($interval -and ((Get-Date) - $lastScavenge) -gt ($interval * 2)) {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Server Scavenging' -Target $ComputerName `
                -Status 'Warn' -Finding "Last scavenge was $lastScavenge, more than 2x the configured interval ($interval) ago."))
    }
    else {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Server Scavenging' -Target $ComputerName `
                -Status 'Pass' -Finding "Scavenging last ran $lastScavenge, interval $interval."))
    }

    $results
}

function Test-DnsListenerConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $Inventory
    )

    if (-not $Inventory.ListeningIPs -or $Inventory.ListeningIPs.Count -eq 0) {
        return New-DiagResult -Category 'DNS' -TestName 'Listener Configuration' -Target $ComputerName `
            -Status 'Pass' -Finding 'Server listens on all IP addresses (no explicit list configured).'
    }

    $missing = @($Inventory.ListeningIPs | Where-Object { $_ -notin $Inventory.NicIPs })
    if ($missing.Count -gt 0) {
        New-DiagResult -Category 'DNS' -TestName 'Listener Configuration' -Target $ComputerName `
            -Status 'Warn' -Finding "Configured listening IP(s) not present on any NIC: $($missing -join ', ')." `
            -Detail 'Likely a stale listener config left over from an IP change.'
    }
    else {
        New-DiagResult -Category 'DNS' -TestName 'Listener Configuration' -Target $ComputerName `
            -Status 'Pass' -Finding 'Listening IPs match configured NIC addresses.'
    }
}

# --- DNS zone-level (design 5.2) ---

function Test-DnsZoneReplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] [hashtable] $DnsData
    )

    $hostingServers = @($DnsData.Keys | Where-Object { $DnsData[$_].Zones.ContainsKey($ZoneName) })
    if ($hostingServers.Count -le 1) {
        return New-DiagResult -Category 'DNS' -TestName 'Zone Replication' -Target $ZoneName `
            -Status 'Info' -Finding "Zone observed on $($hostingServers.Count) of $($DnsData.Keys.Count) queried DNS server(s)."
    }

    $zoneInfos = $hostingServers | ForEach-Object {
        $zoneRow = $DnsData[$_].Inventory.Zones | Where-Object ZoneName -eq $ZoneName | Select-Object -First 1
        [PSCustomObject]@{ Server = $_; ZoneType = $zoneRow.ZoneType; ReplicationScope = $zoneRow.ReplicationScope }
    }

    $inconsistent = (@($zoneInfos.ZoneType | Select-Object -Unique)).Count -gt 1 -or
        (@($zoneInfos.ReplicationScope | Select-Object -Unique)).Count -gt 1
    $missingFrom = @($DnsData.Keys | Where-Object { $_ -notin $hostingServers })

    if ($inconsistent) {
        $summary = ($zoneInfos | ForEach-Object { "$($_.Server): Type=$($_.ZoneType), Repl=$($_.ReplicationScope)" }) -join '; '
        New-DiagResult -Category 'DNS' -TestName 'Zone Replication' -Target $ZoneName `
            -Status 'Fail' -Finding 'Zone type/replication scope is inconsistent across DNS servers.' -Detail $summary
    }
    elseif ($missingFrom.Count -gt 0) {
        New-DiagResult -Category 'DNS' -TestName 'Zone Replication' -Target $ZoneName `
            -Status 'Warn' -Finding "Zone is missing from: $($missingFrom -join ', ')."
    }
    else {
        New-DiagResult -Category 'DNS' -TestName 'Zone Replication' -Target $ZoneName `
            -Status 'Pass' -Finding "Zone consistently present on all $($hostingServers.Count) queried DNS servers."
    }
}

function Test-DnsSoaNsSanity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] [hashtable] $DnsData
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $hostingServers = @($DnsData.Keys | Where-Object { $DnsData[$_].Zones.ContainsKey($ZoneName) })

    $serials = $hostingServers | ForEach-Object {
        [PSCustomObject]@{ Server = $_; Serial = $DnsData[$_].Zones[$ZoneName].Detail.SoaSerial }
    }
    $uniqueSerials = @($serials.Serial | Select-Object -Unique)

    if ($uniqueSerials.Count -gt 1) {
        $summary = ($serials | ForEach-Object { "$($_.Server)=$($_.Serial)" }) -join '; '
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'SOA Serial Consistency' -Target $ZoneName `
                -Status 'Fail' -Finding 'SOA serial differs across authoritative servers (replication lag or split-brain).' -Detail $summary))
    }
    else {
        $results.Add((New-DiagResult -Category 'DNS' -TestName 'SOA Serial Consistency' -Target $ZoneName `
                -Status 'Pass' -Finding "SOA serial consistent ($($uniqueSerials[0])) across $($hostingServers.Count) server(s)."))
    }

    $nameServers = @($hostingServers | ForEach-Object { $DnsData[$_].Zones[$ZoneName].Detail.NameServers } | Select-Object -Unique)
    foreach ($ns in $nameServers) {
        try {
            $null = Resolve-DnsName -Server $ns -Name $ZoneName -Type SOA -QuickTimeout -ErrorAction Stop
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'NS Authority Check' -Target "$ZoneName -> $ns" `
                    -Status 'Pass' -Finding "$ns answers authoritatively for $ZoneName."))
        }
        catch {
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'NS Authority Check' -Target "$ZoneName -> $ns" `
                    -Status 'Fail' -Finding "$ns did not answer for $ZoneName (possibly a decommissioned DC): $($_.Exception.Message)"))
        }
    }

    $results
}

function Test-DnsZoneAging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] $ZoneDetail
    )

    if (-not $ZoneDetail.AgingEnabled) {
        return New-DiagResult -Category 'DNS' -TestName 'Zone Aging Configuration' -Target "$ComputerName\$ZoneName" `
            -Status 'Info' -Finding 'Aging/scavenging is disabled on this zone.'
    }

    if (-not $ZoneDetail.NoRefreshInterval -or -not $ZoneDetail.RefreshInterval -or
        $ZoneDetail.NoRefreshInterval.TotalHours -eq 0 -or $ZoneDetail.RefreshInterval.TotalHours -eq 0) {
        return New-DiagResult -Category 'DNS' -TestName 'Zone Aging Configuration' -Target "$ComputerName\$ZoneName" `
            -Status 'Warn' -Finding 'Aging is enabled but no-refresh/refresh interval is zero or unset.'
    }

    New-DiagResult -Category 'DNS' -TestName 'Zone Aging Configuration' -Target "$ComputerName\$ZoneName" `
        -Status 'Pass' -Finding "Aging enabled: no-refresh $($ZoneDetail.NoRefreshInterval), refresh $($ZoneDetail.RefreshInterval)." `
        -Detail 'DHCP lease duration alignment check arrives in Phase 3.'
}

function Test-DnsStaleRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] $ZoneDetail,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Records,
        [int] $StaleThresholdDays
    )

    $effectiveThreshold = if ($StaleThresholdDays -gt 0) {
        $StaleThresholdDays
    }
    elseif ($ZoneDetail.AgingEnabled -and $ZoneDetail.NoRefreshInterval -and $ZoneDetail.RefreshInterval) {
        [Math]::Ceiling($ZoneDetail.NoRefreshInterval.TotalDays + $ZoneDetail.RefreshInterval.TotalDays)
    }
    else {
        30
    }

    $staticRecords = @($Records | Where-Object IsStatic)
    $dynamicRecords = @($Records | Where-Object { -not $_.IsStatic })
    $staleRecords = @($dynamicRecords | Where-Object { $_.Timestamp -and $_.Timestamp -lt (Get-Date).AddDays(-$effectiveThreshold) })

    $status = if ($staleRecords.Count -gt 0) { 'Warn' } else { 'Pass' }
    New-DiagResult -Category 'DNS' -TestName 'Stale Record Analysis' -Target "$ComputerName\$ZoneName" `
        -Status $status -Finding "$($staleRecords.Count) dynamic record(s) older than $effectiveThreshold day(s); $($staticRecords.Count) static record(s) in inventory." `
        -Data ([PSCustomObject]@{ ThresholdDays = $effectiveThreshold; StaleCount = $staleRecords.Count; StaticCount = $staticRecords.Count; DynamicCount = $dynamicRecords.Count })
}

function Test-DnsDuplicateRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Records,
        [switch] $IsReverseZone,
        [hashtable] $ForwardHostnamesByIp
    )

    $results = [System.Collections.Generic.List[object]]::new()

    if (-not $IsReverseZone) {
        $aRecords = @($Records | Where-Object RecordType -eq 'A')

        $multiA = @($aRecords | Group-Object HostName | Where-Object { $_.Count -gt 1 })
        if ($multiA.Count -gt 0) {
            $names = ($multiA | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Duplicate A Records' -Target "$ComputerName\$ZoneName" `
                    -Status 'Info' -Finding "$($multiA.Count) name(s) with multiple A records: $names" `
                    -Detail 'May be intentional round-robin; review individually.'))
        }
        else {
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Duplicate A Records' -Target "$ComputerName\$ZoneName" `
                    -Status 'Pass' -Finding 'No names with multiple A records.'))
        }

        $multiName = @($aRecords | Group-Object RecordData | Where-Object { $_.Count -gt 1 })
        if ($multiName.Count -gt 0) {
            $ips = ($multiName | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Multiple Names Per IP' -Target "$ComputerName\$ZoneName" `
                    -Status 'Info' -Finding "$($multiName.Count) IP(s) shared by multiple names: $ips"))
        }
    }
    else {
        $ptrRecords = @($Records | Where-Object RecordType -eq 'PTR')
        $mismatches = @()
        if ($ForwardHostnamesByIp) {
            foreach ($ptr in $ptrRecords) {
                $ip = ConvertFrom-PtrRecordToIp -ZoneName $ZoneName -HostName $ptr.HostName
                if (-not $ip) { continue }
                $expectedHost = $ForwardHostnamesByIp[$ip]
                $ptrTarget = $ptr.RecordData.TrimEnd('.')
                if ($expectedHost -and $expectedHost -ne $ptrTarget) {
                    $mismatches += "$ip -> PTR=$ptrTarget but forward A says $expectedHost"
                }
            }
        }

        if ($mismatches.Count -gt 0) {
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'PTR/A Coverage' -Target "$ComputerName\$ZoneName" `
                    -Status 'Warn' -Finding "$($mismatches.Count) PTR/A mismatch(es) found." -Detail ($mismatches -join '; ')))
        }
        else {
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'PTR/A Coverage' -Target "$ComputerName\$ZoneName" `
                    -Status 'Info' -Finding "$($ptrRecords.Count) PTR record(s); no mismatches detected against known forward records."))
        }
    }

    $results
}

function Test-DnsDelegationHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $ZoneName,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Records
    )

    $delegationNs = @($Records | Where-Object { $_.RecordType -eq 'NS' -and $_.HostName -and $_.HostName -ne '@' })
    if ($delegationNs.Count -eq 0) {
        return New-DiagResult -Category 'DNS' -TestName 'Delegation Health' -Target "$ComputerName\$ZoneName" `
            -Status 'Info' -Finding 'No child zone delegations found.'
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($delegation in $delegationNs) {
        $childName = "$($delegation.HostName).$ZoneName"
        $nsTarget = $delegation.RecordData.TrimEnd('.')
        $glueExists = [bool]($Records | Where-Object { $_.RecordType -eq 'A' -and "$($_.HostName).$ZoneName" -eq $nsTarget })

        try {
            $null = Resolve-DnsName -Server $nsTarget -Name $childName -Type SOA -QuickTimeout -ErrorAction Stop
            $answering = $true
        }
        catch {
            $answering = $false
        }

        if ($answering -and ($glueExists -or $nsTarget -notlike "*.$ZoneName")) {
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Delegation Health' -Target "$ComputerName\$childName" `
                    -Status 'Pass' -Finding "Delegation to $nsTarget is healthy and answering."))
        }
        else {
            $reason = if (-not $answering) { "$nsTarget did not answer for $childName" } else { "missing in-zone glue A record for $nsTarget" }
            $results.Add((New-DiagResult -Category 'DNS' -TestName 'Delegation Health' -Target "$ComputerName\$childName" `
                    -Status 'Fail' -Finding $reason))
        }
    }

    $results
}

# --- DHCP server-level (design 5.3) ---

function Test-DhcpServerHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $Inventory
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Service Health' -Target $ComputerName `
            -Status $(if ($Inventory.ServiceState -eq 'Running') { 'Pass' } else { 'Fail' }) `
            -Finding "DHCP Server service state: $($Inventory.ServiceState)."))

    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Authorization' -Target $ComputerName `
            -Status $(if ($Inventory.IsAuthorized) { 'Pass' } else { 'Fail' }) `
            -Finding "Server is $(if ($Inventory.IsAuthorized) { '' } else { 'NOT ' })authorized in AD."))

    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Audit Logging' -Target $ComputerName `
            -Status $(if ($Inventory.AuditLogEnabled) { 'Pass' } else { 'Warn' }) `
            -Finding "Audit logging is $(if ($Inventory.AuditLogEnabled) { 'enabled' } else { 'disabled' })."))

    $results
}

# --- DHCP scope-level (design 5.3) ---

function Test-DhcpScopeUtilization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $ScopeDetail
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $pctInUse = $ScopeDetail.PercentageInUse

    $status = if ($pctInUse -ge 95) { 'Fail' } elseif ($pctInUse -ge 80) { 'Warn' } else { 'Pass' }
    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Scope Utilization' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status $status -Finding "$pctInUse% of scope in use ($($ScopeDetail.AddressesInUse) used, $($ScopeDetail.AddressesFree) free)." `
            -Data ([PSCustomObject]@{ PercentageInUse = $pctInUse; AddressesInUse = $ScopeDetail.AddressesInUse; AddressesFree = $ScopeDetail.AddressesFree })))

    if ($ScopeDetail.State -ne 'Active') {
        $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Scope State' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
                -Status 'Info' -Finding "Scope state is $($ScopeDetail.State)."))
    }

    $results
}

function Test-DhcpReservations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $ScopeDetail,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Leases
    )

    $reservations = @($Leases | Where-Object Type -eq 'Reservation')
    if ($reservations.Count -eq 0) {
        return New-DiagResult -Category 'DHCP' -TestName 'Reservations' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status 'Info' -Finding 'No reservations configured.'
    }

    $startNum = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($ScopeDetail.StartRange))
    $endNum = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($ScopeDetail.EndRange))
    $badReservations = @()

    foreach ($reservation in $reservations) {
        try { $ipNum = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($reservation.IPAddress)) }
        catch { continue }

        $inRange = $ipNum -ge $startNum -and $ipNum -le $endNum
        $inExclusion = $false
        foreach ($exclusion in $ScopeDetail.ExclusionRanges) {
            try {
                $exStart = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($exclusion.StartRange))
                $exEnd = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($exclusion.EndRange))
                if ($ipNum -ge $exStart -and $ipNum -le $exEnd) { $inExclusion = $true; break }
            }
            catch { continue }
        }

        if (-not $inRange -or $inExclusion) {
            $reason = if (-not $inRange) { 'outside scope range' } else { 'inside an exclusion range' }
            $badReservations += "$($reservation.IPAddress) ($reason)"
        }
    }

    if ($badReservations.Count -gt 0) {
        New-DiagResult -Category 'DHCP' -TestName 'Reservations' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status 'Fail' -Finding "$($badReservations.Count) reservation(s) misconfigured." -Detail ($badReservations -join '; ')
    }
    else {
        New-DiagResult -Category 'DHCP' -TestName 'Reservations' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status 'Pass' -Finding "$($reservations.Count) reservation(s), all within scope range and outside exclusions."
    }
}

function Test-DhcpOptionsAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $ScopeDetail,
        [string[]] $KnownDnsServers
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $options = $ScopeDetail.Options

    $router = $options | Where-Object OptionId -eq 3
    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Option 003 Router' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status $(if ($router) { 'Pass' } else { 'Warn' }) `
            -Finding $(if ($router) { "Router option set to $($router.Value -join ', ')." } else { 'No router (003) option configured.' })))

    $domainName = $options | Where-Object OptionId -eq 15
    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Option 015 Domain Name' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status $(if ($domainName) { 'Pass' } else { 'Info' }) `
            -Finding $(if ($domainName) { "Domain name option set to $($domainName.Value -join ', ')." } else { 'No domain name (015) option configured.' })))

    $dnsOption = $options | Where-Object OptionId -eq 6
    if (-not $dnsOption -or -not $dnsOption.Value) {
        $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Option 006 DNS Servers' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
                -Status 'Warn' -Finding 'No DNS servers (006) option configured.'))
    }
    else {
        foreach ($dnsIp in $dnsOption.Value) {
            $answers = $false
            try {
                $null = Resolve-DnsName -Server $dnsIp -Name '.' -Type NS -QuickTimeout -ErrorAction Stop
                $answers = $true
            }
            catch { $answers = $false }

            if (-not $answers) {
                $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Option 006 DNS Servers' -Target "$ComputerName\$($ScopeDetail.ScopeId) -> $dnsIp" `
                        -Status 'Fail' -Finding "DNS server $dnsIp did not answer a query."))
            }
            elseif ($KnownDnsServers -and $dnsIp -notin $KnownDnsServers) {
                $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Option 006 DNS Servers' -Target "$ComputerName\$($ScopeDetail.ScopeId) -> $dnsIp" `
                        -Status 'Warn' -Finding "DNS server $dnsIp answers but is not among the diagnosed domain DNS servers."))
            }
            else {
                $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Option 006 DNS Servers' -Target "$ComputerName\$($ScopeDetail.ScopeId) -> $dnsIp" `
                        -Status 'Pass' -Finding "DNS server $dnsIp is answering."))
            }
        }
    }

    $results
}

function Test-DhcpFailover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $ScopeDetail,
        [Parameter(Mandatory)] [bool] $ServerHasAnyFailover
    )

    if ($ScopeDetail.FailoverRelationship) {
        $partnerReachable = $false
        try {
            $partnerReachable = [bool](Test-Connection -ComputerName $ScopeDetail.FailoverPartner -Count 1 -Quiet -ErrorAction Stop)
        }
        catch { $partnerReachable = $false }

        $status = if ($partnerReachable) { 'Pass' } else { 'Fail' }
        return New-DiagResult -Category 'DHCP' -TestName 'Failover' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status $status -Finding "In relationship '$($ScopeDetail.FailoverRelationship)' ($($ScopeDetail.FailoverMode)) with partner $($ScopeDetail.FailoverPartner), state $($ScopeDetail.FailoverState); partner $(if ($partnerReachable) { 'reachable' } else { 'unreachable' })."
    }

    if ($ServerHasAnyFailover) {
        New-DiagResult -Category 'DHCP' -TestName 'Failover' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status 'Warn' -Finding 'Scope is not in any failover relationship, but other scopes on this server are.'
    }
    else {
        New-DiagResult -Category 'DHCP' -TestName 'Failover' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status 'Info' -Finding 'No failover relationships configured on this server.'
    }
}

function Test-DhcpConflictExclusions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] $ScopeDetail
    )

    $results = [System.Collections.Generic.List[object]]::new()

    $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Conflict Detection' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
            -Status $(if ($ScopeDetail.ConflictDetectionAttempts -gt 0) { 'Pass' } else { 'Info' }) `
            -Finding "Conflict detection attempts: $($ScopeDetail.ConflictDetectionAttempts)."))

    try {
        $totalAddresses = (ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($ScopeDetail.EndRange))) -
                           (ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($ScopeDetail.StartRange))) + 1
        $excludedAddresses = 0
        foreach ($exclusion in $ScopeDetail.ExclusionRanges) {
            $exStart = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($exclusion.StartRange))
            $exEnd = ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($exclusion.EndRange))
            $excludedAddresses += ($exEnd - $exStart + 1)
        }
        $pctExcluded = if ($totalAddresses -gt 0) { [Math]::Round(($excludedAddresses / $totalAddresses) * 100, 1) } else { 0 }

        $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Exclusion Coverage' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
                -Status 'Info' -Finding "$($ScopeDetail.ExclusionRanges.Count) exclusion range(s) covering $excludedAddresses of $totalAddresses addresses ($pctExcluded%)."))
    }
    catch {
        $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Exclusion Coverage' -Target "$ComputerName\$($ScopeDetail.ScopeId)" `
                -Status 'Error' -Finding "Could not compute exclusion coverage: $($_.Exception.Message)"))
    }

    $results
}

#endregion Analyzers

#region Renderers

function Export-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] [hashtable] $Collected,
        [Parameter(Mandatory)] [string] $OutputPath,
        [switch] $RawDump
    )

    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $flatResults = $Results | ForEach-Object {
        $dataString = ''
        if ($_.Data) {
            $dataString = ($_.Data.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        }
        [PSCustomObject]@{
            Category  = $_.Category
            TestName  = $_.TestName
            Target    = $_.Target
            Status    = $_.Status
            Finding   = $_.Finding
            Detail    = $_.Detail
            Data      = $dataString
            Timestamp = $_.Timestamp
        }
    }
    $flatResults | Export-Csv -Path (Join-Path $OutputPath 'TestResults.csv') -NoTypeInformation -Encoding UTF8

    if ($RawDump) {
        foreach ($bucket in $Collected.Keys) {
            $rows = @($Collected[$bucket])
            if ($rows.Count -gt 0) {
                $fileName = "$(ConvertTo-SafeFileName $bucket).csv"
                $rows | Export-Csv -Path (Join-Path $OutputPath $fileName) -NoTypeInformation -Encoding UTF8
            }
        }
    }

    Write-DiagLog "Results exported to $OutputPath"
}

function Show-SummaryReport {
    # Design doc section 6.1. Pure renderer: consumes $Results and the small
    # $RunContext header info only, no data access of its own.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] $RunContext
    )

    $useColor = $Host.UI.SupportsVirtualTerminal
    function Write-Heading([string] $Text, [string] $Color) {
        if ($useColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    }

    Write-Host ''
    Write-Heading '=== DNS/DHCP Diagnostics Summary ===' 'Cyan'
    Write-Host "  DNS servers  : $($RunContext.DnsServers -join ', ')"
    Write-Host "  DHCP servers : $($RunContext.DhcpServers -join ', ')"
    Write-Host "  Zones        : $($RunContext.ZoneCount)"
    Write-Host "  Scopes       : $($RunContext.ScopeCount)"
    Write-Host "  Run as       : $($RunContext.CredentialUserName)"
    Write-Host "  Started      : $($RunContext.StartTime)"
    Write-Host "  Duration     : $($RunContext.Duration.ToString('mm\:ss'))"
    Write-Host ''

    $severityOrder = @{ Fail = 0; Error = 1; Warn = 2; Info = 3; Pass = 4 }
    foreach ($category in ($Results | Group-Object Category)) {
        $counts = $category.Group | Group-Object Status | Sort-Object { $severityOrder[$_.Name] }
        $summary = ($counts | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ' / '
        Write-Host "  $($category.Name): $summary"
    }
    Write-Host ''

    $actionable = @($Results | Where-Object Status -in 'Fail', 'Error', 'Warn' | Sort-Object { $severityOrder[$_.Status] })
    if ($actionable.Count -gt 0) {
        Write-Heading "--- Findings requiring attention ($($actionable.Count)) ---" 'Yellow'
        $actionable | Format-Table Category, TestName, Target, Status, Finding -AutoSize -Wrap | Out-Host
    }
    else {
        Write-Heading '--- No Warn/Fail/Error findings ---' 'Green'
    }

    $passResults = @($Results | Where-Object Status -eq 'Pass')
    if ($VerbosePreference -eq 'Continue' -and $passResults.Count -gt 0) {
        $passResults | Format-Table Category, TestName, Target, Status, Finding -AutoSize -Wrap | Out-Host
    }
    else {
        Write-Host "  ($($passResults.Count) Pass result(s) collapsed; re-run with -Verbose to see them all)"
    }

    Write-Host ''
    if ($RunContext.OutputPath) {
        Write-Heading "Full results exported to: $($RunContext.OutputPath)" 'Cyan'
    }
    Write-Host ''
}

#endregion Renderers

#region Main

function Invoke-Main {
    [CmdletBinding()]
    param()

    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    $script:LogFilePath = Join-Path $OutputPath 'Run.log'

    $startTime = Get-Date
    Write-DiagLog "Run started. Tests=$($Tests -join ','); Mode=$Mode; OutputPath=$OutputPath"

    Test-RequiredModule

    $targets = Resolve-TargetServers -DnsServer $DnsServer -DhcpServer $DhcpServer -Credential $Credential
    Write-DiagLog "DNS servers: $($targets.DnsServers -join ', ')"
    Write-DiagLog "DHCP servers: $($targets.DhcpServers -join ', ')"

    $effectiveTests = if ($Tests -contains 'All') { @('Dns', 'Dhcp', 'Ddns') } else { $Tests }

    $results = [System.Collections.Generic.List[object]]::new()
    $collected = @{}

    $dnsCim = @{}
    $dhcpCim = @{}
    if ($Credential) {
        if ($targets.DnsServers) { $dnsCim = New-DiagCimSession -ComputerName $targets.DnsServers -Credential $Credential }
        if ($targets.DhcpServers) { $dhcpCim = New-DiagCimSession -ComputerName $targets.DhcpServers -Credential $Credential }
    }

    $reachableDns = @()
    if ($targets.DnsServers -and ($effectiveTests -contains 'Dns' -or $effectiveTests -contains 'Ddns')) {
        $dnsConnResults = @(Test-ServerConnectivity -ComputerName $targets.DnsServers -Category 'DNS')
        $dnsConnResults | ForEach-Object { $results.Add($_) }
        $reachableDns = $dnsConnResults | Where-Object Status -eq 'Pass' | Select-Object -ExpandProperty Target
    }

    $reachableDhcp = @()
    if ($targets.DhcpServers -and ($effectiveTests -contains 'Dhcp' -or $effectiveTests -contains 'Ddns')) {
        $dhcpConnResults = @(Test-ServerConnectivity -ComputerName $targets.DhcpServers -Category 'DHCP')
        $dhcpConnResults | ForEach-Object { $results.Add($_) }
        $reachableDhcp = $dhcpConnResults | Where-Object Status -eq 'Pass' | Select-Object -ExpandProperty Target
    }

    # ============================================================
    # Stage 1: Collection — same collectors as Phase 1, but staged into
    # $dnsData/$dhcpData (keyed by server, then zone/scope) so Stage 2
    # analyzers get full cross-server/cross-scope visibility instead of
    # a single interleaved pass. Record/lease dumps are now always fetched
    # (analyzers need them); -RawDump still only controls whether they're
    # also written out as CSV.
    # ============================================================
    $dnsData = @{}
    $dhcpData = @{}

    if ($effectiveTests -contains 'Dns') {
        foreach ($dnsServer in $reachableDns) {
            Write-DiagLog "Collecting DNS inventory from $dnsServer"
            try {
                $inventory = Get-DnsInventory -ComputerName $dnsServer -CimSession $dnsCim[$dnsServer]
                Add-CollectedRow -Collected $collected -Bucket 'DNS_Zones' -Rows $inventory.Zones
                $dnsData[$dnsServer] = @{ Inventory = $inventory; Zones = @{} }

                $zoneRows = $inventory.Zones
                if ($Zone) { $zoneRows = $zoneRows | Where-Object { $_.ZoneName -in $Zone } }
                if (-not $IncludeReverseZones) { $zoneRows = $zoneRows | Where-Object { $_.ZoneName -notmatch '\.(in-addr|ip6)\.arpa$' } }

                foreach ($zoneRow in $zoneRows) {
                    $zoneName = $zoneRow.ZoneName
                    try {
                        $zoneDetail = Get-DnsZoneDetail -ComputerName $dnsServer -ZoneName $zoneName -CimSession $dnsCim[$dnsServer]
                        Add-CollectedRow -Collected $collected -Bucket 'DNS_ZoneDetail' -Rows @($zoneDetail)

                        $recordRows = @(Get-DnsRecordDump -ComputerName $dnsServer -ZoneName $zoneName -CimSession $dnsCim[$dnsServer])
                        if ($RawDump) {
                            Add-CollectedRow -Collected $collected -Bucket "DNS_Records_$(ConvertTo-SafeFileName $zoneName)" -Rows $recordRows
                        }

                        $dnsData[$dnsServer].Zones[$zoneName] = @{
                            Detail       = $zoneDetail
                            Records      = $recordRows
                            IsReverseZone = [bool]$zoneRow.IsReverseLookupZone
                        }
                    }
                    catch {
                        $results.Add((New-DiagResult -Category 'DNS' -TestName 'Zone Collection' -Target "$dnsServer\$zoneName" `
                                    -Status 'Error' -Finding "Failed to collect zone detail: $($_.Exception.Message)"))
                    }
                }
            }
            catch {
                $results.Add((New-DiagResult -Category 'DNS' -TestName 'Server Collection' -Target $dnsServer `
                            -Status 'Error' -Finding "Failed to collect DNS inventory: $($_.Exception.Message)"))
            }
        }
    }

    if ($effectiveTests -contains 'Dhcp') {
        foreach ($dhcpServer in $reachableDhcp) {
            Write-DiagLog "Collecting DHCP inventory from $dhcpServer"
            try {
                $inventory = Get-DhcpInventory -ComputerName $dhcpServer -CimSession $dhcpCim[$dhcpServer]
                Add-CollectedRow -Collected $collected -Bucket 'DHCP_Servers' -Rows @($inventory)
                $dhcpData[$dhcpServer] = @{ Inventory = $inventory; Scopes = @{} }

                $dhcpCimParam = if ($dhcpCim[$dhcpServer]) { @{ CimSession = $dhcpCim[$dhcpServer] } } else { @{ ComputerName = $dhcpServer } }
                $scopeIds = Get-DhcpServerv4Scope @dhcpCimParam -ErrorAction Stop | Select-Object -ExpandProperty ScopeId | ForEach-Object { $_.IPAddressToString }
                if ($Scope) { $scopeIds = $scopeIds | Where-Object { $_ -in $Scope } }

                foreach ($scopeId in $scopeIds) {
                    try {
                        $scopeDetail = Get-DhcpScopeDetail -ComputerName $dhcpServer -ScopeId $scopeId -CimSession $dhcpCim[$dhcpServer]
                        Add-CollectedRow -Collected $collected -Bucket 'DHCP_Scopes' -Rows @($scopeDetail | Select-Object * -ExcludeProperty Options, ExclusionRanges)
                        Add-CollectedRow -Collected $collected -Bucket 'DHCP_Options' -Rows @($scopeDetail.Options | ForEach-Object {
                                [PSCustomObject]@{ DhcpServer = $dhcpServer; ScopeId = $scopeId; OptionId = $_.OptionId; Name = $_.Name; Value = ($_.Value -join ',') }
                            })

                        $leaseRows = @(Get-DhcpLeaseDump -ComputerName $dhcpServer -ScopeId $scopeId -CimSession $dhcpCim[$dhcpServer])
                        if ($RawDump) {
                            Add-CollectedRow -Collected $collected -Bucket "DHCP_Leases_$(ConvertTo-SafeFileName $scopeId)" -Rows $leaseRows
                            Add-CollectedRow -Collected $collected -Bucket 'DHCP_Reservations' -Rows @($leaseRows | Where-Object Type -eq 'Reservation')
                        }

                        $dhcpData[$dhcpServer].Scopes[$scopeId] = @{ Detail = $scopeDetail; Leases = $leaseRows }
                    }
                    catch {
                        $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Scope Collection' -Target "$dhcpServer\$scopeId" `
                                    -Status 'Error' -Finding "Failed to collect scope detail: $($_.Exception.Message)"))
                    }
                }
            }
            catch {
                $results.Add((New-DiagResult -Category 'DHCP' -TestName 'Server Collection' -Target $dhcpServer `
                            -Status 'Error' -Finding "Failed to collect DHCP inventory: $($_.Exception.Message)"))
            }
        }
    }

    # --- DDNS raw config collection (analysis lands in Phase 3) ---
    if ($effectiveTests -contains 'Ddns') {
        foreach ($dhcpServer in $reachableDhcp) {
            try {
                $serverSetting = Get-DdnsConfiguration -ComputerName $dhcpServer -CimSession $dhcpCim[$dhcpServer]
                Add-CollectedRow -Collected $collected -Bucket 'DHCP_DdnsSettings' -Rows @($serverSetting)

                $dhcpCimParam = if ($dhcpCim[$dhcpServer]) { @{ CimSession = $dhcpCim[$dhcpServer] } } else { @{ ComputerName = $dhcpServer } }
                $scopeIds = Get-DhcpServerv4Scope @dhcpCimParam -ErrorAction Stop | Select-Object -ExpandProperty ScopeId | ForEach-Object { $_.IPAddressToString }
                if ($Scope) { $scopeIds = $scopeIds | Where-Object { $_ -in $Scope } }
                foreach ($scopeId in $scopeIds) {
                    $scopeSetting = Get-DdnsConfiguration -ComputerName $dhcpServer -ScopeId $scopeId -CimSession $dhcpCim[$dhcpServer]
                    Add-CollectedRow -Collected $collected -Bucket 'DHCP_DdnsSettings' -Rows @($scopeSetting)
                }
            }
            catch {
                $results.Add((New-DiagResult -Category 'DDNS' -TestName 'DDNS Config Collection' -Target $dhcpServer `
                            -Status 'Error' -Finding "Failed to collect DDNS configuration: $($_.Exception.Message)"))
            }
        }

        foreach ($dnsServer in $reachableDns) {
            try {
                $inventory = Get-DnsInventory -ComputerName $dnsServer -CimSession $dnsCim[$dnsServer]
                $zoneNames = $inventory.Zones | Where-Object IsDsIntegrated | Select-Object -ExpandProperty ZoneName
                if ($Zone) { $zoneNames = $zoneNames | Where-Object { $_ -in $Zone } }
                if (-not $IncludeReverseZones) { $zoneNames = $zoneNames | Where-Object { $_ -notmatch '\.(in-addr|ip6)\.arpa$' } }

                foreach ($zoneName in $zoneNames) {
                    try {
                        $ownershipRows = @(Get-RecordOwnership -ComputerName $dnsServer -ZoneName $zoneName -FullScan:$FullOwnershipScan)
                        Add-CollectedRow -Collected $collected -Bucket 'DNS_RecordOwnership' -Rows $ownershipRows
                    }
                    catch {
                        $results.Add((New-DiagResult -Category 'DDNS' -TestName 'Record Ownership Sampling' -Target "$dnsServer\$zoneName" `
                                    -Status 'Error' -Finding "Failed to sample record ownership: $($_.Exception.Message)"))
                    }
                }
            }
            catch {
                $results.Add((New-DiagResult -Category 'DDNS' -TestName 'Record Ownership Sampling' -Target $dnsServer `
                            -Status 'Error' -Finding "Failed to enumerate zones for ownership sampling: $($_.Exception.Message)"))
            }
        }
    }

    # ============================================================
    # Stage 2: Analysis — design 5.1-5.3 test catalog against the data
    # staged above. DDNS analyzers (design 5.4) are Phase 3; the DDNS raw
    # config gathered above is exported but not yet evaluated.
    # ============================================================
    Write-DiagLog 'Running analyzers.'

    $knownDnsIPs = @()
    foreach ($server in $targets.DnsServers) {
        try {
            $knownDnsIPs += [System.Net.Dns]::GetHostAddresses($server) |
                Where-Object AddressFamily -eq 'InterNetwork' | ForEach-Object { $_.IPAddressToString }
        }
        catch {
            Write-DiagLog "Could not resolve $server to an IP for the DHCP option-006 cross-check: $($_.Exception.Message)" 'WARN'
        }
    }
    $knownDnsIPs = @($knownDnsIPs | Select-Object -Unique)

    # DNS server-level (5.1)
    foreach ($dnsServer in $dnsData.Keys) {
        $inv = $dnsData[$dnsServer].Inventory
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Service Health' -Target $dnsServer -ScriptBlock { Test-DnsServiceHealth -ComputerName $dnsServer -Inventory $inv }
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Responsiveness' -Target $dnsServer -ScriptBlock { Test-DnsResponsiveness -ComputerName $dnsServer -Inventory $inv }
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Forwarders & Root Hints' -Target $dnsServer -ScriptBlock { Test-DnsForwarders -ComputerName $dnsServer -Inventory $inv }
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Recursion/Scavenging' -Target $dnsServer -ScriptBlock { Test-DnsRecursionScavenging -ComputerName $dnsServer -Inventory $inv }
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Listener Configuration' -Target $dnsServer -ScriptBlock { Test-DnsListenerConfig -ComputerName $dnsServer -Inventory $inv }
    }

    # Forward A-record map per server, only needed for the PTR/A cross-check when reverse zones are in scope.
    $forwardHostnamesByIp = @{}
    if ($IncludeReverseZones) {
        foreach ($dnsServer in $dnsData.Keys) {
            $map = @{}
            foreach ($entry in $dnsData[$dnsServer].Zones.GetEnumerator()) {
                if ($entry.Value.IsReverseZone) { continue }
                foreach ($rec in ($entry.Value.Records | Where-Object RecordType -eq 'A')) {
                    $map[$rec.RecordData] = "$($rec.HostName).$($entry.Key)"
                }
            }
            $forwardHostnamesByIp[$dnsServer] = $map
        }
    }

    # DNS zone-level (5.2), per-server checks
    foreach ($dnsServer in $dnsData.Keys) {
        foreach ($zoneName in $dnsData[$dnsServer].Zones.Keys) {
            $zoneEntry = $dnsData[$dnsServer].Zones[$zoneName]
            Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Zone Aging Configuration' -Target "$dnsServer\$zoneName" -ScriptBlock { Test-DnsZoneAging -ComputerName $dnsServer -ZoneName $zoneName -ZoneDetail $zoneEntry.Detail }
            Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Stale Record Analysis' -Target "$dnsServer\$zoneName" -ScriptBlock { Test-DnsStaleRecords -ComputerName $dnsServer -ZoneName $zoneName -ZoneDetail $zoneEntry.Detail -Records $zoneEntry.Records -StaleThresholdDays $StaleThresholdDays }
            Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Duplicate Record Analysis' -Target "$dnsServer\$zoneName" -ScriptBlock { Test-DnsDuplicateRecords -ComputerName $dnsServer -ZoneName $zoneName -Records $zoneEntry.Records -IsReverseZone:$zoneEntry.IsReverseZone -ForwardHostnamesByIp $forwardHostnamesByIp[$dnsServer] }
            Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Delegation Health' -Target "$dnsServer\$zoneName" -ScriptBlock { Test-DnsDelegationHealth -ComputerName $dnsServer -ZoneName $zoneName -Records $zoneEntry.Records }
        }
    }

    # DNS zone-level (5.2), cross-server checks — once per unique zone name
    $allZoneNames = @($dnsData.Values | ForEach-Object { $_.Zones.Keys } | Select-Object -Unique)
    foreach ($zoneName in $allZoneNames) {
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'Zone Replication' -Target $zoneName -ScriptBlock { Test-DnsZoneReplication -ZoneName $zoneName -DnsData $dnsData }
        Invoke-Analyzer -ResultList $results -Category 'DNS' -TestName 'SOA/NS Sanity' -Target $zoneName -ScriptBlock { Test-DnsSoaNsSanity -ZoneName $zoneName -DnsData $dnsData }
    }

    # DHCP server-level (5.3)
    foreach ($dhcpServer in $dhcpData.Keys) {
        $inv = $dhcpData[$dhcpServer].Inventory
        Invoke-Analyzer -ResultList $results -Category 'DHCP' -TestName 'Server Health' -Target $dhcpServer -ScriptBlock { Test-DhcpServerHealth -ComputerName $dhcpServer -Inventory $inv }
    }

    # DHCP scope-level (5.3)
    foreach ($dhcpServer in $dhcpData.Keys) {
        $serverHasAnyFailover = [bool]($dhcpData[$dhcpServer].Scopes.Values | Where-Object { $_.Detail.FailoverRelationship })
        foreach ($scopeId in $dhcpData[$dhcpServer].Scopes.Keys) {
            $scopeEntry = $dhcpData[$dhcpServer].Scopes[$scopeId]
            Invoke-Analyzer -ResultList $results -Category 'DHCP' -TestName 'Scope Utilization' -Target "$dhcpServer\$scopeId" -ScriptBlock { Test-DhcpScopeUtilization -ComputerName $dhcpServer -ScopeDetail $scopeEntry.Detail }
            Invoke-Analyzer -ResultList $results -Category 'DHCP' -TestName 'Reservations' -Target "$dhcpServer\$scopeId" -ScriptBlock { Test-DhcpReservations -ComputerName $dhcpServer -ScopeDetail $scopeEntry.Detail -Leases $scopeEntry.Leases }
            Invoke-Analyzer -ResultList $results -Category 'DHCP' -TestName 'Options Audit' -Target "$dhcpServer\$scopeId" -ScriptBlock { Test-DhcpOptionsAudit -ComputerName $dhcpServer -ScopeDetail $scopeEntry.Detail -KnownDnsServers $knownDnsIPs }
            Invoke-Analyzer -ResultList $results -Category 'DHCP' -TestName 'Failover' -Target "$dhcpServer\$scopeId" -ScriptBlock { Test-DhcpFailover -ComputerName $dhcpServer -ScopeDetail $scopeEntry.Detail -ServerHasAnyFailover $serverHasAnyFailover }
            Invoke-Analyzer -ResultList $results -Category 'DHCP' -TestName 'Conflict Detection & Exclusions' -Target "$dhcpServer\$scopeId" -ScriptBlock { Test-DhcpConflictExclusions -ComputerName $dhcpServer -ScopeDetail $scopeEntry.Detail }
        }
    }

    $duration = (Get-Date) - $startTime
    $runContext = [PSCustomObject]@{
        DnsServers         = $targets.DnsServers
        DhcpServers        = $targets.DhcpServers
        ZoneCount          = $allZoneNames.Count
        ScopeCount         = ($dhcpData.Values | ForEach-Object { $_.Scopes.Keys }).Count
        CredentialUserName = if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }
        StartTime          = $startTime
        Duration           = $duration
        OutputPath         = if ($Mode -in 'Export', 'Both') { $OutputPath } else { $null }
    }

    if ($Mode -in 'Export', 'Both') {
        Export-Results -Results $results -Collected $collected -OutputPath $OutputPath -RawDump:$RawDump
    }
    if ($Mode -in 'Report', 'Both') {
        Show-SummaryReport -Results $results -RunContext $runContext
    }

    Write-DiagLog "Run complete in $($duration.ToString('mm\:ss'))."
    Write-Host "Output written to: $OutputPath"

    foreach ($session in ($dnsCim.Values + $dhcpCim.Values)) {
        Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
    }

    if ($PassThru) {
        return $results
    }
}

Invoke-Main

#endregion Main
