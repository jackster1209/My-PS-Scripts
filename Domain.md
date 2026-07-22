# Active Directory Domain Deployment Checklist
**Project:** New AD Domain — 2x Windows Server 2022 Domain Controllers
**Date started:** ____________  **Lead:** ____________

---

## Phase 1 — Planning & Decisions
Lock these down before touching any hardware.

- [ ] Domain FQDN chosen (e.g. `corp.example.com`): ____________
- [ ] NetBIOS name chosen (≤15 chars, e.g. `CORP`): ____________
- [ ] Hostnames assigned (e.g. `DC01`, `DC02`): ____________ / ____________
- [ ] Static IPs allocated for both DCs: ____________ / ____________
- [ ] Default gateway and subnet mask confirmed: ____________
- [ ] DSRM (Directory Services Restore Mode) password set and stored in password manager
- [ ] Forest/domain functional level decided (default: `WinThreshold` / 2016)
- [ ] External NTP source identified for PDC emulator time sync
- [ ] Confirmed role for each server (both DCs vs. one DC + one member server)
- [ ] Decided whether a reverse lookup zone is needed

## Phase 2 — Server Prep (perform on EACH server)

- [ ] Static IP, gateway, and subnet configured
- [ ] DC01 DNS pointed temporarily at itself (`127.0.0.1`)
- [ ] DC02 DNS pointed at DC01's IP
- [ ] Hostname set on each server
- [ ] Servers rebooted after rename
- [ ] Both servers fully patched / Windows Update complete
- [ ] Time source verified on both servers

## Phase 3 — Build the Forest (DC01)

- [ ] `AD-Domain-Services` role installed with management tools
- [ ] `Install-ADDSForest` run with correct domain, NetBIOS, and functional levels
- [ ] DNS install confirmed (`-InstallDns:$true`)
- [ ] DSRM password entered when prompted
- [ ] DC01 rebooted automatically and came back up
- [ ] Confirmed DC01 is a Global Catalog
- [ ] Confirmed DC01 holds all five FSMO roles

## Phase 4 — Add the Second DC (DC02)

- [ ] DC02 DNS confirmed pointing at DC01 (must resolve the domain)
- [ ] `AD-Domain-Services` role installed with management tools
- [ ] `Install-ADDSDomainController` run with domain admin credentials
- [ ] Correct site name specified (e.g. `Default-First-Site-Name`)
- [ ] Global Catalog enabled on DC02
- [ ] DC02 rebooted and came back up
- [ ] DNS client order fixed — each DC points at the OTHER first, then itself
  - [ ] DC01 → DC02's IP, then `127.0.0.1`
  - [ ] DC02 → DC01's IP, then `127.0.0.1`

## Phase 5 — Verification & Hardening

- [ ] `dcdiag /v` run on each DC — all tests pass
- [ ] `repadmin /replsummary` shows healthy replication
- [ ] `repadmin /showrepl` reviewed per-partner with no errors
- [ ] `Get-ADDomainController -Filter *` lists both DCs
- [ ] `netdom query fsmo` confirms role placement
- [ ] `Get-ADReplicationPartnerMetadata` reviewed at forest scope
- [ ] PDC emulator (DC01) configured to sync from external NTP source
- [ ] Reverse lookup zone created (if not auto-created)
- [ ] DHCP scopes updated to hand out BOTH DCs as DNS servers (if applicable)

## Phase 6 — Post-Deployment (optional but recommended)

- [ ] Default OU structure created
- [ ] Baseline Group Policy reviewed (Default Domain Policy)
- [ ] DC backup / system state backup configured
- [ ] Monitoring/alerting hooked up for replication and DC health
- [ ] Documentation updated with final IPs, names, and credentials location
