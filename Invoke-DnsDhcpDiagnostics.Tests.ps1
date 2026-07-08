# Pester tests for the Test-*/analyzer functions and pure-math shared
# helpers in Invoke-DnsDhcpDiagnostics.ps1, using hand-built mock objects
# matching the collector output shapes documented throughout the script.
# Collectors (Get-Dns*/Get-Dhcp*) are intentionally not unit tested here —
# they're thin wrappers over RSAT cmdlets unavailable on non-Windows hosts;
# that's an integration-test concern for a real environment.
#
# Coverage is representative (Pass + one Warn/Fail/Info branch per
# analyzer), not exhaustive branch coverage, per the design doc's own
# framing ("Pester tests for analyzers using mocked collector output").

BeforeAll {
    # Resolve-DnsName is a Windows-only (DnsClient module) cmdlet not
    # present on non-Windows hosts; Pester's Mock needs *something* to
    # shadow, so pre-declare a stub when the real cmdlet isn't available.
    # Test-Connection is a real cross-platform PS7 cmdlet, no stub needed.
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        function Resolve-DnsName { param() }
    }

    . "$PSScriptRoot/Invoke-DnsDhcpDiagnostics.ps1"
}

#region Shared pure-math / string helpers

Describe 'ConvertTo-UInt32FromIp' {
    It 'converts <IP> to <Expected>' -TestCases @(
        @{ IP = '0.0.0.0'; Expected = 0 }
        @{ IP = '0.0.0.1'; Expected = 1 }
        @{ IP = '10.38.10.5'; Expected = 170265093 }
        @{ IP = '255.255.255.255'; Expected = 4294967295 }
        @{ IP = '192.168.1.100'; Expected = 3232235876 }
    ) {
        ConvertTo-UInt32FromIp ([System.Net.IPAddress]::Parse($IP)) | Should -Be $Expected
    }
}

Describe 'ConvertFrom-PtrRecordToIp' {
    It 'reconstructs an IP from a /24-style in-addr.arpa zone + host label' {
        ConvertFrom-PtrRecordToIp -ZoneName '10.38.10.in-addr.arpa' -HostName '5' | Should -Be '10.38.10.5'
    }
    It 'returns $null for non in-addr.arpa zones' {
        ConvertFrom-PtrRecordToIp -ZoneName 'contoso.com' -HostName '5' | Should -BeNullOrEmpty
    }
    It 'returns $null for a non-numeric host label' {
        ConvertFrom-PtrRecordToIp -ZoneName '10.38.10.in-addr.arpa' -HostName 'notanumber' | Should -BeNullOrEmpty
    }
    It 'returns $null for a non-/24 zone (wrong label count)' {
        ConvertFrom-PtrRecordToIp -ZoneName '10.in-addr.arpa' -HostName '5' | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-PtrZoneAndHost' {
    It 'computes the assumed /24 reverse zone name and host label' {
        $result = ConvertTo-PtrZoneAndHost -IPAddress '10.38.10.5'
        $result.ZoneName | Should -Be '10.38.10.in-addr.arpa'
        $result.HostName | Should -Be '5'
    }
    It 'round-trips with ConvertFrom-PtrRecordToIp' {
        $result = ConvertTo-PtrZoneAndHost -IPAddress '192.168.1.100'
        ConvertFrom-PtrRecordToIp -ZoneName $result.ZoneName -HostName $result.HostName | Should -Be '192.168.1.100'
    }
    It 'returns $null for a malformed address' {
        ConvertTo-PtrZoneAndHost -IPAddress '10.38.10' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ComputerAccountName' {
    It 'appends $ to the leftmost label of an FQDN' {
        Get-ComputerAccountName -ComputerName 'dhcp01.contoso.com' | Should -Be 'dhcp01$'
    }
    It 'appends $ to a bare hostname' {
        Get-ComputerAccountName -ComputerName 'DHCP01' | Should -Be 'DHCP01$'
    }
}

#endregion

#region DNS server-level analyzers (design 5.1)

Describe 'Test-DnsServiceHealth' {
    It 'Passes when the service is Running' {
        $r = Test-DnsServiceHealth -ComputerName 'dc1' -Inventory ([PSCustomObject]@{ ServiceState = 'Running' })
        $r.Status | Should -Be 'Pass'
    }
    It 'Fails when the service is Stopped' {
        $r = Test-DnsServiceHealth -ComputerName 'dc1' -Inventory ([PSCustomObject]@{ ServiceState = 'Stopped' })
        $r.Status | Should -Be 'Fail'
    }
    It 'Errors when the service state could not be determined' {
        $r = Test-DnsServiceHealth -ComputerName 'dc1' -Inventory ([PSCustomObject]@{ ServiceState = $null })
        $r.Status | Should -Be 'Error'
    }
}

Describe 'Test-DnsResponsiveness' {
    It 'reports Info when there is no forward zone to probe' {
        $inv = [PSCustomObject]@{ Zones = @() }
        $r = Test-DnsResponsiveness -ComputerName 'dc1' -Inventory $inv
        $r.Status | Should -Be 'Info'
    }
    It 'Passes when the SOA probe succeeds' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'SOA' } }
        $inv = [PSCustomObject]@{ Zones = @([PSCustomObject]@{ ZoneName = 'contoso.com'; IsReverseLookupZone = $false; IsAutoCreated = $false }) }
        $r = Test-DnsResponsiveness -ComputerName 'dc1' -Inventory $inv
        $r.Status | Should -Be 'Pass'
    }
    It 'Fails when the SOA probe throws' {
        Mock Resolve-DnsName { throw 'no answer' }
        $inv = [PSCustomObject]@{ Zones = @([PSCustomObject]@{ ZoneName = 'contoso.com'; IsReverseLookupZone = $false; IsAutoCreated = $false }) }
        $r = Test-DnsResponsiveness -ComputerName 'dc1' -Inventory $inv
        $r.Status | Should -Be 'Fail'
    }
}

Describe 'Test-DnsForwarders' {
    It 'Warns when there are no forwarders and no root hints' {
        $inv = [PSCustomObject]@{ Forwarders = @(); RootHintCount = 0 }
        $r = Test-DnsForwarders -ComputerName 'dc1' -Inventory $inv
        $r.Status | Should -Be 'Warn'
    }
    It 'Passes for each forwarder that answers' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'NS' } }
        $inv = [PSCustomObject]@{ Forwarders = @('8.8.8.8'); RootHintCount = 13 }
        $r = @(Test-DnsForwarders -ComputerName 'dc1' -Inventory $inv)
        ($r | Where-Object Target -eq 'dc1 -> 8.8.8.8').Status | Should -Be 'Pass'
    }
    It 'Fails for a forwarder that does not answer' {
        Mock Resolve-DnsName { throw 'timeout' }
        $inv = [PSCustomObject]@{ Forwarders = @('10.0.0.1'); RootHintCount = 13 }
        $r = @(Test-DnsForwarders -ComputerName 'dc1' -Inventory $inv)
        ($r | Where-Object Target -eq 'dc1 -> 10.0.0.1').Status | Should -Be 'Fail'
    }
}

Describe 'Test-DnsRecursionScavenging' {
    It 'Warns when scavenging is enabled but has never run' {
        $inv = [PSCustomObject]@{ RecursionEnabled = $true; ScavengingEnabled = $true; ScavengingInterval = [timespan]'7.00:00:00'; LastScavengeTime = $null }
        $r = @(Test-DnsRecursionScavenging -ComputerName 'dc1' -Inventory $inv)
        ($r | Where-Object TestName -eq 'Server Scavenging').Status | Should -Be 'Warn'
    }
    It 'Passes when scavenging last ran within 2x the interval' {
        $inv = [PSCustomObject]@{ RecursionEnabled = $true; ScavengingEnabled = $true; ScavengingInterval = [timespan]'7.00:00:00'; LastScavengeTime = (Get-Date).AddDays(-1) }
        $r = @(Test-DnsRecursionScavenging -ComputerName 'dc1' -Inventory $inv)
        ($r | Where-Object TestName -eq 'Server Scavenging').Status | Should -Be 'Pass'
    }
    It 'reports Info when scavenging is disabled' {
        $inv = [PSCustomObject]@{ RecursionEnabled = $false; ScavengingEnabled = $false }
        $r = @(Test-DnsRecursionScavenging -ComputerName 'dc1' -Inventory $inv)
        ($r | Where-Object TestName -eq 'Server Scavenging').Status | Should -Be 'Info'
    }
}

Describe 'Test-DnsListenerConfig' {
    It 'Passes when there is no explicit listening list' {
        $inv = [PSCustomObject]@{ ListeningIPs = @(); NicIPs = @('10.0.0.1') }
        (Test-DnsListenerConfig -ComputerName 'dc1' -Inventory $inv).Status | Should -Be 'Pass'
    }
    It 'Warns when a listening IP is not on any NIC' {
        $inv = [PSCustomObject]@{ ListeningIPs = @('10.0.0.99'); NicIPs = @('10.0.0.1') }
        (Test-DnsListenerConfig -ComputerName 'dc1' -Inventory $inv).Status | Should -Be 'Warn'
    }
}

#endregion

#region DNS zone-level analyzers (design 5.2)

Describe 'Test-DnsZoneReplication' {
    It 'reports Info when the zone is only observed on one server' {
        $dnsData = @{ 'dc1' = @{ Zones = @{ 'contoso.com' = @{} }; Inventory = @{ Zones = @() } } }
        (Test-DnsZoneReplication -ZoneName 'contoso.com' -DnsData $dnsData).Status | Should -Be 'Info'
    }
    It 'Passes when zone type/replication scope are consistent across servers' {
        $zoneRow = [PSCustomObject]@{ ZoneName = 'contoso.com'; ZoneType = 'Primary'; ReplicationScope = 'Domain' }
        $dnsData = @{
            'dc1' = @{ Zones = @{ 'contoso.com' = @{} }; Inventory = @{ Zones = @($zoneRow) } }
            'dc2' = @{ Zones = @{ 'contoso.com' = @{} }; Inventory = @{ Zones = @($zoneRow) } }
        }
        (Test-DnsZoneReplication -ZoneName 'contoso.com' -DnsData $dnsData).Status | Should -Be 'Pass'
    }
    It 'Fails when replication scope is inconsistent across servers' {
        $dnsData = @{
            'dc1' = @{ Zones = @{ 'contoso.com' = @{} }; Inventory = @{ Zones = @([PSCustomObject]@{ ZoneName = 'contoso.com'; ZoneType = 'Primary'; ReplicationScope = 'Domain' }) } }
            'dc2' = @{ Zones = @{ 'contoso.com' = @{} }; Inventory = @{ Zones = @([PSCustomObject]@{ ZoneName = 'contoso.com'; ZoneType = 'Primary'; ReplicationScope = 'Forest' }) } }
        }
        (Test-DnsZoneReplication -ZoneName 'contoso.com' -DnsData $dnsData).Status | Should -Be 'Fail'
    }
    It 'Warns when the zone is missing from some queried servers' {
        $zoneRow = [PSCustomObject]@{ ZoneName = 'contoso.com'; ZoneType = 'Primary'; ReplicationScope = 'Domain' }
        $dnsData = @{
            'dc1' = @{ Zones = @{ 'contoso.com' = @{} }; Inventory = @{ Zones = @($zoneRow) } }
            'dc2' = @{ Zones = @{}; Inventory = @{ Zones = @() } }
        }
        (Test-DnsZoneReplication -ZoneName 'contoso.com' -DnsData $dnsData).Status | Should -Be 'Warn'
    }
}

Describe 'Test-DnsSoaNsSanity' {
    It 'Passes when the SOA serial is consistent and NS servers answer' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'SOA' } }
        $dnsData = @{
            'dc1' = @{ Zones = @{ 'contoso.com' = @{ Detail = [PSCustomObject]@{ SoaSerial = 100; NameServers = @('dc1.contoso.com') } } } }
        }
        $r = @(Test-DnsSoaNsSanity -ZoneName 'contoso.com' -DnsData $dnsData)
        ($r | Where-Object TestName -eq 'SOA Serial Consistency').Status | Should -Be 'Pass'
        ($r | Where-Object TestName -eq 'NS Authority Check').Status | Should -Be 'Pass'
    }
    It 'Fails when SOA serials differ across servers' {
        $dnsData = @{
            'dc1' = @{ Zones = @{ 'contoso.com' = @{ Detail = [PSCustomObject]@{ SoaSerial = 100; NameServers = @() } } } }
            'dc2' = @{ Zones = @{ 'contoso.com' = @{ Detail = [PSCustomObject]@{ SoaSerial = 99; NameServers = @() } } } }
        }
        $r = Test-DnsSoaNsSanity -ZoneName 'contoso.com' -DnsData $dnsData
        ($r | Where-Object TestName -eq 'SOA Serial Consistency').Status | Should -Be 'Fail'
    }
    It 'Fails the NS check when a name server does not answer' {
        Mock Resolve-DnsName { throw 'no answer' }
        $dnsData = @{ 'dc1' = @{ Zones = @{ 'contoso.com' = @{ Detail = [PSCustomObject]@{ SoaSerial = 100; NameServers = @('old-dc.contoso.com') } } } } }
        $r = Test-DnsSoaNsSanity -ZoneName 'contoso.com' -DnsData $dnsData
        ($r | Where-Object TestName -eq 'NS Authority Check').Status | Should -Be 'Fail'
    }
}

Describe 'Test-DnsZoneAging' {
    It 'reports Info when aging is disabled' {
        $detail = [PSCustomObject]@{ AgingEnabled = $false }
        (Test-DnsZoneAging -ComputerName 'dc1' -ZoneName 'contoso.com' -ZoneDetail $detail).Status | Should -Be 'Info'
    }
    It 'Warns when aging is enabled but intervals are zero' {
        $detail = [PSCustomObject]@{ AgingEnabled = $true; NoRefreshInterval = [timespan]::Zero; RefreshInterval = [timespan]::Zero }
        (Test-DnsZoneAging -ComputerName 'dc1' -ZoneName 'contoso.com' -ZoneDetail $detail).Status | Should -Be 'Warn'
    }
    It 'Passes when aging is enabled with sane intervals' {
        $detail = [PSCustomObject]@{ AgingEnabled = $true; NoRefreshInterval = [timespan]'7.00:00:00'; RefreshInterval = [timespan]'7.00:00:00' }
        (Test-DnsZoneAging -ComputerName 'dc1' -ZoneName 'contoso.com' -ZoneDetail $detail).Status | Should -Be 'Pass'
    }
}

Describe 'Test-DnsStaleRecords' {
    BeforeAll {
        $zoneDetail = [PSCustomObject]@{ AgingEnabled = $false }
    }

    It 'Passes when no dynamic records are older than the threshold' {
        $records = @([PSCustomObject]@{ IsStatic = $false; Timestamp = (Get-Date) })
        $r = Test-DnsStaleRecords -ComputerName 'dc1' -ZoneName 'contoso.com' -ZoneDetail $zoneDetail -Records $records -StaleThresholdDays 30
        $r.Status | Should -Be 'Pass'
    }
    It 'Warns when dynamic records are older than the threshold' {
        $records = @([PSCustomObject]@{ IsStatic = $false; Timestamp = (Get-Date).AddDays(-100) })
        $r = Test-DnsStaleRecords -ComputerName 'dc1' -ZoneName 'contoso.com' -ZoneDetail $zoneDetail -Records $records -StaleThresholdDays 30
        $r.Status | Should -Be 'Warn'
    }
    It 'derives the threshold from zone aging when none is supplied' {
        $agingDetail = [PSCustomObject]@{ AgingEnabled = $true; NoRefreshInterval = [timespan]'5.00:00:00'; RefreshInterval = [timespan]'5.00:00:00' }
        $records = @([PSCustomObject]@{ IsStatic = $false; Timestamp = (Get-Date).AddDays(-1) })
        $r = Test-DnsStaleRecords -ComputerName 'dc1' -ZoneName 'contoso.com' -ZoneDetail $agingDetail -Records $records -StaleThresholdDays 0
        $r.Data.ThresholdDays | Should -Be 10
    }
}

Describe 'Test-DnsDuplicateRecords' {
    It 'Passes when there are no duplicate A records' {
        $records = @([PSCustomObject]@{ HostName = 'www'; RecordType = 'A'; RecordData = '10.0.0.1' })
        $r = @(Test-DnsDuplicateRecords -ComputerName 'dc1' -ZoneName 'contoso.com' -Records $records)
        ($r | Where-Object TestName -eq 'Duplicate A Records').Status | Should -Be 'Pass'
    }
    It 'reports Info when the same name has multiple A records' {
        $records = @(
            [PSCustomObject]@{ HostName = 'www'; RecordType = 'A'; RecordData = '10.0.0.1' }
            [PSCustomObject]@{ HostName = 'www'; RecordType = 'A'; RecordData = '10.0.0.2' }
        )
        $r = @(Test-DnsDuplicateRecords -ComputerName 'dc1' -ZoneName 'contoso.com' -Records $records)
        ($r | Where-Object TestName -eq 'Duplicate A Records').Status | Should -Be 'Info'
    }
    It 'Warns on a PTR/A mismatch in a reverse zone' {
        $records = @([PSCustomObject]@{ HostName = '5'; RecordType = 'PTR'; RecordData = 'wrong.contoso.com.' })
        $forwardMap = @{ '10.38.10.5' = 'right.contoso.com' }
        $r = Test-DnsDuplicateRecords -ComputerName 'dc1' -ZoneName '10.38.10.in-addr.arpa' -Records $records -IsReverseZone -ForwardHostnamesByIp $forwardMap
        $r.Status | Should -Be 'Warn'
    }
}

Describe 'Test-DnsDelegationHealth' {
    It 'reports Info when there are no delegations' {
        $records = @([PSCustomObject]@{ RecordType = 'A'; HostName = 'www' })
        (Test-DnsDelegationHealth -ComputerName 'dc1' -ZoneName 'contoso.com' -Records $records).Status | Should -Be 'Info'
    }
    It 'Passes a delegation with glue that answers' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'SOA' } }
        $records = @(
            [PSCustomObject]@{ RecordType = 'NS'; HostName = 'child'; RecordData = 'ns1.child.contoso.com.' }
            [PSCustomObject]@{ RecordType = 'A'; HostName = 'ns1.child'; RecordData = '10.0.0.5' }
        )
        $r = Test-DnsDelegationHealth -ComputerName 'dc1' -ZoneName 'contoso.com' -Records $records
        $r.Status | Should -Be 'Pass'
    }
    It 'Fails a delegation whose NS does not answer' {
        Mock Resolve-DnsName { throw 'no answer' }
        $records = @([PSCustomObject]@{ RecordType = 'NS'; HostName = 'child'; RecordData = 'ns1.child.contoso.com.' })
        $r = Test-DnsDelegationHealth -ComputerName 'dc1' -ZoneName 'contoso.com' -Records $records
        $r.Status | Should -Be 'Fail'
    }
}

#endregion

#region DHCP server/scope-level analyzers (design 5.3)

Describe 'Test-DhcpServerHealth' {
    It 'Passes all three checks when healthy' {
        $inv = [PSCustomObject]@{ ServiceState = 'Running'; IsAuthorized = $true; AuditLogEnabled = $true }
        $r = @(Test-DhcpServerHealth -ComputerName 'dhcp1' -Inventory $inv)
        ($r | Where-Object Status -ne 'Pass').Count | Should -Be 0
    }
    It 'Fails authorization when the server is not authorized' {
        $inv = [PSCustomObject]@{ ServiceState = 'Running'; IsAuthorized = $false; AuditLogEnabled = $true }
        $r = @(Test-DhcpServerHealth -ComputerName 'dhcp1' -Inventory $inv)
        ($r | Where-Object TestName -eq 'Authorization').Status | Should -Be 'Fail'
    }
}

Describe 'Test-DhcpScopeUtilization' {
    It 'Passes below 80% utilization' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; PercentageInUse = 50; AddressesInUse = 50; AddressesFree = 50; State = 'Active' }
        $r = @(Test-DhcpScopeUtilization -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Scope Utilization').Status | Should -Be 'Pass'
    }
    It 'Warns at 80%+ utilization' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; PercentageInUse = 85; AddressesInUse = 85; AddressesFree = 15; State = 'Active' }
        $r = @(Test-DhcpScopeUtilization -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Scope Utilization').Status | Should -Be 'Warn'
    }
    It 'Fails at 95%+ utilization' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; PercentageInUse = 99; AddressesInUse = 99; AddressesFree = 1; State = 'Active' }
        $r = @(Test-DhcpScopeUtilization -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Scope Utilization').Status | Should -Be 'Fail'
    }
    It 'reports Info when the scope is inactive' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; PercentageInUse = 10; AddressesInUse = 1; AddressesFree = 9; State = 'Inactive' }
        $r = @(Test-DhcpScopeUtilization -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Scope State').Status | Should -Be 'Info'
    }
}

Describe 'Test-DhcpReservations' {
    BeforeAll {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; StartRange = '10.0.0.10'; EndRange = '10.0.0.200'; ExclusionRanges = @() }
    }

    It 'reports Info when there are no reservations' {
        (Test-DhcpReservations -ComputerName 'dhcp1' -ScopeDetail $scope -Leases @()).Status | Should -Be 'Info'
    }
    It 'Passes when all reservations are in-range and unexcluded' {
        $leases = @([PSCustomObject]@{ Type = 'Reservation'; IPAddress = '10.0.0.50' })
        (Test-DhcpReservations -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases).Status | Should -Be 'Pass'
    }
    It 'Fails when a reservation IP is outside the scope range' {
        $leases = @([PSCustomObject]@{ Type = 'Reservation'; IPAddress = '10.0.5.50' })
        (Test-DhcpReservations -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases).Status | Should -Be 'Fail'
    }
    It 'Fails when a reservation IP falls inside an exclusion range' {
        $scopeWithExclusion = [PSCustomObject]@{ ScopeId = '10.0.0.0'; StartRange = '10.0.0.10'; EndRange = '10.0.0.200'; ExclusionRanges = @([PSCustomObject]@{ StartRange = '10.0.0.40'; EndRange = '10.0.0.60' }) }
        $leases = @([PSCustomObject]@{ Type = 'Reservation'; IPAddress = '10.0.0.50' })
        (Test-DhcpReservations -ComputerName 'dhcp1' -ScopeDetail $scopeWithExclusion -Leases $leases).Status | Should -Be 'Fail'
    }
}

Describe 'Test-DhcpOptionsAudit' {
    It 'Warns when option 003 (router) is missing' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @() }
        $r = @(Test-DhcpOptionsAudit -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Option 003 Router').Status | Should -Be 'Warn'
    }
    It 'Passes option 006 for a DNS server that answers and is known' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'NS' } }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 6; Name = 'DNS Servers'; Value = @('10.0.0.1') }) }
        $r = @(Test-DhcpOptionsAudit -ComputerName 'dhcp1' -ScopeDetail $scope -KnownDnsServers @('10.0.0.1'))
        ($r | Where-Object TestName -eq 'Option 006 DNS Servers').Status | Should -Be 'Pass'
    }
    It 'Fails option 006 for a DNS server that does not answer' {
        Mock Resolve-DnsName { throw 'timeout' }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 6; Name = 'DNS Servers'; Value = @('10.0.0.99') }) }
        $r = @(Test-DhcpOptionsAudit -ComputerName 'dhcp1' -ScopeDetail $scope -KnownDnsServers @('10.0.0.1'))
        ($r | Where-Object TestName -eq 'Option 006 DNS Servers').Status | Should -Be 'Fail'
    }
    It 'Warns option 006 for a DNS server that answers but is not a known domain DNS server' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'NS' } }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 6; Name = 'DNS Servers'; Value = @('8.8.8.8') }) }
        $r = @(Test-DhcpOptionsAudit -ComputerName 'dhcp1' -ScopeDetail $scope -KnownDnsServers @('10.0.0.1'))
        ($r | Where-Object TestName -eq 'Option 006 DNS Servers').Status | Should -Be 'Warn'
    }
}

Describe 'Test-DhcpFailover' {
    It 'Passes when a failover partner is reachable' {
        Mock Test-Connection { $true }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; FailoverRelationship = 'rel1'; FailoverMode = 'LoadBalance'; FailoverPartner = 'dhcp2'; FailoverState = 'Normal' }
        (Test-DhcpFailover -ComputerName 'dhcp1' -ScopeDetail $scope -ServerHasAnyFailover $true).Status | Should -Be 'Pass'
    }
    It 'Fails when a failover partner is unreachable' {
        Mock Test-Connection { $false }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; FailoverRelationship = 'rel1'; FailoverMode = 'LoadBalance'; FailoverPartner = 'dhcp2'; FailoverState = 'Normal' }
        (Test-DhcpFailover -ComputerName 'dhcp1' -ScopeDetail $scope -ServerHasAnyFailover $true).Status | Should -Be 'Fail'
    }
    It 'Warns when this scope has no failover but sibling scopes do' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; FailoverRelationship = $null }
        (Test-DhcpFailover -ComputerName 'dhcp1' -ScopeDetail $scope -ServerHasAnyFailover $true).Status | Should -Be 'Warn'
    }
    It 'reports Info when no failover exists anywhere on the server' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; FailoverRelationship = $null }
        (Test-DhcpFailover -ComputerName 'dhcp1' -ScopeDetail $scope -ServerHasAnyFailover $false).Status | Should -Be 'Info'
    }
}

Describe 'Test-DhcpConflictExclusions' {
    It 'reports exclusion coverage and conflict detection attempts' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; ConflictDetectionAttempts = 2; StartRange = '10.0.0.1'; EndRange = '10.0.0.254'; ExclusionRanges = @([PSCustomObject]@{ StartRange = '10.0.0.1'; EndRange = '10.0.0.10' }) }
        $r = @(Test-DhcpConflictExclusions -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Conflict Detection').Status | Should -Be 'Pass'
        ($r | Where-Object TestName -eq 'Exclusion Coverage').Status | Should -Be 'Info'
    }
    It 'reports Info conflict detection when attempts is zero' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; ConflictDetectionAttempts = 0; StartRange = '10.0.0.1'; EndRange = '10.0.0.254'; ExclusionRanges = @() }
        $r = @(Test-DhcpConflictExclusions -ComputerName 'dhcp1' -ScopeDetail $scope)
        ($r | Where-Object TestName -eq 'Conflict Detection').Status | Should -Be 'Info'
    }
}

#endregion

#region DDNS tandem analyzers (design 5.4)

Describe 'Test-DdnsUpdateSettings' {
    It 'reports Info-only when lease cleanup is enabled' {
        $setting = [PSCustomObject]@{ DynamicUpdates = 'Always'; NameProtection = $true; UpdateDnsRRForOlderClients = $true; DeleteDnsRROnLeaseExpiry = $true }
        $r = @(Test-DdnsUpdateSettings -ComputerName 'dhcp1' -ScopeId '10.0.0.0' -ScopeSetting $setting)
        $r.Count | Should -Be 1
    }
    It 'Warns when dynamic updates are on but lease-expiry cleanup is off' {
        $setting = [PSCustomObject]@{ DynamicUpdates = 'Always'; NameProtection = $true; UpdateDnsRRForOlderClients = $true; DeleteDnsRROnLeaseExpiry = $false }
        $r = @(Test-DdnsUpdateSettings -ComputerName 'dhcp1' -ScopeId '10.0.0.0' -ScopeSetting $setting)
        ($r | Where-Object TestName -eq 'Lease Expiry Cleanup').Status | Should -Be 'Warn'
    }
    It 'does not warn about cleanup when dynamic updates are disabled' {
        $setting = [PSCustomObject]@{ DynamicUpdates = 'Never'; NameProtection = $false; UpdateDnsRRForOlderClients = $false; DeleteDnsRROnLeaseExpiry = $false }
        $r = @(Test-DdnsUpdateSettings -ComputerName 'dhcp1' -ScopeId '10.0.0.0' -ScopeSetting $setting)
        $r.Count | Should -Be 1
    }
}

Describe 'Test-DdnsCredential' {
    It 'reports Info when dynamic updates are disabled everywhere' {
        $setting = [PSCustomObject]@{ DnsCredentialConfigured = $false }
        (Test-DdnsCredential -ComputerName 'dhcp1' -ServerSetting $setting -AnyScopeHasDynamicUpdates $false).Status | Should -Be 'Info'
    }
    It 'Passes when a dedicated credential is configured' {
        $setting = [PSCustomObject]@{ DnsCredentialConfigured = $true; DnsCredentialUserName = 'CONTOSO\svc-ddns' }
        (Test-DdnsCredential -ComputerName 'dhcp1' -ServerSetting $setting -AnyScopeHasDynamicUpdates $true).Status | Should -Be 'Pass'
    }
    It 'Fails when dynamic updates are enabled with no dedicated credential' {
        $setting = [PSCustomObject]@{ DnsCredentialConfigured = $false }
        (Test-DdnsCredential -ComputerName 'dhcp1' -ServerSetting $setting -AnyScopeHasDynamicUpdates $true).Status | Should -Be 'Fail'
    }
}

Describe 'Test-DdnsUpdateProxyHygiene' {
    It 'Passes when there are no hygiene issues' {
        $setting = [PSCustomObject]@{ DnsUpdateProxyMembers = @(); NameProtection = $true; DnsCredentialConfigured = $false }
        (Test-DdnsUpdateProxyHygiene -ComputerName 'dhcp1.contoso.com' -ServerSetting $setting).Status | Should -Be 'Pass'
    }
    It 'Warns when the DHCP computer account is a proxy member with Name Protection off' {
        $setting = [PSCustomObject]@{ DnsUpdateProxyMembers = @('dhcp1$'); NameProtection = $false; DnsCredentialConfigured = $false }
        $r = @(Test-DdnsUpdateProxyHygiene -ComputerName 'dhcp1.contoso.com' -ServerSetting $setting)
        ($r | Where-Object Status -eq 'Warn').Count | Should -BeGreaterThan 0
    }
    It 'Warns when the dedicated credential account is also a proxy member' {
        $setting = [PSCustomObject]@{ DnsUpdateProxyMembers = @('svc-ddns'); NameProtection = $true; DnsCredentialConfigured = $true; DnsCredentialUserName = 'CONTOSO\svc-ddns' }
        $r = @(Test-DdnsUpdateProxyHygiene -ComputerName 'dhcp1.contoso.com' -ServerSetting $setting)
        ($r | Where-Object Status -eq 'Warn').Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-DdnsRecordOwnership' {
    It 'reports Info when there are no sampled records' {
        (Test-DdnsRecordOwnership -ComputerName 'dc1' -ZoneName 'contoso.com' -Ownership @()).Status | Should -Be 'Info'
    }
    It 'buckets a client self-registered (computer account) owner correctly' {
        $ownership = @([PSCustomObject]@{ Owner = 'CONTOSO\WORKSTATION1$' })
        $r = Test-DdnsRecordOwnership -ComputerName 'dc1' -ZoneName 'contoso.com' -Ownership $ownership -DhcpComputerAccounts @('dhcp1$')
        $r.Data.ClientSelfRegistered | Should -Be 1
    }
    It 'Warns when records are owned by a DHCP computer account with no dedicated credential anywhere' {
        $ownership = @([PSCustomObject]@{ Owner = 'CONTOSO\DHCP1$' })
        $r = Test-DdnsRecordOwnership -ComputerName 'dc1' -ZoneName 'contoso.com' -Ownership $ownership `
            -DhcpComputerAccounts @('CONTOSO\DHCP1$') -AnyDhcpServerMissingCredential $true
        $r.Status | Should -Be 'Warn'
    }
}

Describe 'Test-DdnsLeaseAgingAlignment' {
    It 'returns nothing when the scope has no option-015 domain name' {
        $scope = [PSCustomObject]@{ Options = @() }
        Test-DdnsLeaseAgingAlignment -ComputerName 'dhcp1' -ScopeDetail $scope -DnsData @{} | Should -BeNullOrEmpty
    }
    It 'Warns when the aging window is shorter than the lease duration' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 15; Value = @('contoso.com') }); LeaseDuration = [timespan]'14.00:00:00' }
        $dnsData = @{ 'dc1' = @{ Zones = @{ 'contoso.com' = @{ Detail = [PSCustomObject]@{ AgingEnabled = $true; NoRefreshInterval = [timespan]'3.00:00:00'; RefreshInterval = [timespan]'3.00:00:00' } } } } }
        (Test-DdnsLeaseAgingAlignment -ComputerName 'dhcp1' -ScopeDetail $scope -DnsData $dnsData).Status | Should -Be 'Warn'
    }
    It 'Passes when the aging window comfortably covers the lease duration' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 15; Value = @('contoso.com') }); LeaseDuration = [timespan]'8.00:00:00' }
        $dnsData = @{ 'dc1' = @{ Zones = @{ 'contoso.com' = @{ Detail = [PSCustomObject]@{ AgingEnabled = $true; NoRefreshInterval = [timespan]'7.00:00:00'; RefreshInterval = [timespan]'7.00:00:00' } } } } }
        (Test-DdnsLeaseAgingAlignment -ComputerName 'dhcp1' -ScopeDetail $scope -DnsData $dnsData).Status | Should -Be 'Pass'
    }
}

Describe 'Test-DdnsPtrCoverage' {
    It 'returns nothing when no reverse zones were collected' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0' }
        Test-DdnsPtrCoverage -ComputerName 'dhcp1' -ScopeDetail $scope -Leases @() -EffectiveDynamicUpdates 'Always' -ReverseZoneIndex @{} | Should -BeNullOrEmpty
    }
    It 'Passes when every sampled active lease has a matching PTR' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0' }
        $leases = @([PSCustomObject]@{ Type = 'Lease'; AddressState = 'Active'; IPAddress = '10.38.10.5' })
        $reverseIndex = @{ '10.38.10.in-addr.arpa' = @([PSCustomObject]@{ RecordType = 'PTR'; HostName = '5' }) }
        (Test-DdnsPtrCoverage -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases -EffectiveDynamicUpdates 'Always' -ReverseZoneIndex $reverseIndex).Status | Should -Be 'Pass'
    }
    It 'Warns when a sampled active lease has no matching PTR' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0' }
        $leases = @([PSCustomObject]@{ Type = 'Lease'; AddressState = 'Active'; IPAddress = '10.38.10.5' })
        $reverseIndex = @{ '10.38.10.in-addr.arpa' = @() }
        (Test-DdnsPtrCoverage -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases -EffectiveDynamicUpdates 'Always' -ReverseZoneIndex $reverseIndex).Status | Should -Be 'Warn'
    }
}

Describe 'Test-DdnsLiveRegistration' {
    It 'reports Info when there are no active leases with a hostname' {
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @() }
        (Test-DdnsLiveRegistration -ComputerName 'dhcp1' -ScopeDetail $scope -Leases @() -DnsServers @('dc1')).Status | Should -Be 'Info'
    }
    It 'Passes when the resolved IP matches the leased IP' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'A'; IPAddress = '10.0.0.50' } }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 15; Value = @('contoso.com') }) }
        $leases = @([PSCustomObject]@{ Type = 'Lease'; AddressState = 'Active'; HostName = 'ws1'; IPAddress = '10.0.0.50' })
        (Test-DdnsLiveRegistration -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases -DnsServers @('dc1')).Status | Should -Be 'Pass'
    }
    It 'Fails when the resolved IP differs from the leased IP' {
        Mock Resolve-DnsName { [PSCustomObject]@{ Type = 'A'; IPAddress = '10.0.0.99' } }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 15; Value = @('contoso.com') }) }
        $leases = @([PSCustomObject]@{ Type = 'Lease'; AddressState = 'Active'; HostName = 'ws1'; IPAddress = '10.0.0.50' })
        (Test-DdnsLiveRegistration -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases -DnsServers @('dc1')).Status | Should -Be 'Fail'
    }
    It 'Warns when no DNS record exists at all for a leased host' {
        Mock Resolve-DnsName { throw 'name not found' }
        $scope = [PSCustomObject]@{ ScopeId = '10.0.0.0'; Options = @([PSCustomObject]@{ OptionId = 15; Value = @('contoso.com') }) }
        $leases = @([PSCustomObject]@{ Type = 'Lease'; AddressState = 'Active'; HostName = 'ws1'; IPAddress = '10.0.0.50' })
        (Test-DdnsLiveRegistration -ComputerName 'dhcp1' -ScopeDetail $scope -Leases $leases -DnsServers @('dc1')).Status | Should -Be 'Warn'
    }
}

#endregion
