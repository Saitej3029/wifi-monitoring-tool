from flask import Flask, render_template_string, request, redirect, url_for
import threading
import time
from scapy.all import ARP, Ether, srp
import subprocess
import os

app = Flask(__name__)
authorized_macs = set()

dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Firewall Dashboard (Linux)</title>
    <style>
        body { font-family: Arial; background: #111; color: #eee; padding: 20px; }
        h2 { color: #0ff; }
        form { margin-bottom: 20px; }
        input[type=text] { padding: 8px; width: 300px; }
        button { padding: 8px 12px; margin-left: 5px; background-color: #222; color: #0ff; border: 1px solid #0ff; }
        table { width: 100%%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #444; padding: 10px; text-align: left; }
        tr:hover { background-color: #222; }
    </style>
</head>
<body>
    <h2>WiFi Network Firewall Dashboard (Linux)</h2>
    <form action="/add" method="post">
        <input type="text" name="mac" placeholder="Enter MAC Address (e.g., 00:11:22:33:44:55)" required>
        <button type="submit">Add MAC</button>
    </form>
    <form action="/remove" method="post">
        <input type="text" name="mac" placeholder="Enter MAC Address to Remove" required>
        <button type="submit">Remove MAC</button>
    </form>

    <h3>Authorized MAC Addresses:</h3>
    <table>
        <tr><th>#</th><th>MAC Address</th></tr>
        {% for i, mac in enumerate(mac_list) %}
        <tr><td>{{ i+1 }}</td><td>{{ mac }}</td></tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(dashboard_html, mac_list=sorted(authorized_macs))

@app.route("/add", methods=["POST"])
def add_mac():
    mac = request.form["mac"].strip().lower()
    authorized_macs.add(mac)
    return redirect(url_for("dashboard"))

@app.route("/remove", methods=["POST"])
def remove_mac():
    mac = request.form["mac"].strip().lower()
    authorized_macs.discard(mac)
    return redirect(url_for("dashboard"))

def monitor_network():
    scanned_macs = {}
    while True:
        ip_range = "192.168.1.1/24"  # Update this to match your network
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            mac = received.hwsrc.lower()
            ip = received.psrc

            if mac not in authorized_macs:
                print(f"[BLOCKING] Unauthorized MAC: {mac} ({ip})")
                block_mac_linux(mac)
            else:
                if mac in scanned_macs and scanned_macs[mac] != ip:
                    print(f"[SPOOFING DETECTED] {mac} IP changed from {scanned_macs[mac]} to {ip}")
                    block_mac_linux(mac)
                scanned_macs[mac] = ip
        time.sleep(10)

def block_mac_linux(mac):
    # Check if already blocked
    check = subprocess.run(['iptables', '-L', '-v', '-n'], stdout=subprocess.PIPE)
    if mac in check.stdout.decode():
        return
    # Block using iptables
    subprocess.run(['iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'])

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (sudo)!")
        exit(1)
    threading.Thread(target=monitor_network, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
