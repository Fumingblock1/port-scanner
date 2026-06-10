from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app)

SERVICES = {
    20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",
    8080:"HTTP-alt",8443:"HTTPS-alt",27017:"MongoDB"
}

def scan_port(host, port, timeout, grab_banner):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = ""
                if grab_banner:
                    try:
                        s.sendall(b"\r\n")
                        banner = s.recv(256).decode(errors="replace").strip()[:80]
                    except:
                        pass
                return {"port": port, "state": "open", "service": SERVICES.get(port, "unknown"), "banner": banner}
    except:
        pass
    return None

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    host = data.get("host")
    ports = data.get("ports", [])
    timeout = float(data.get("timeout", 1.0))
    grab_banner = bool(data.get("banners", False))
    threads = int(data.get("threads", 100))

    try:
        ip = socket.gethostbyname(host)
    except:
        return jsonify({"error": f"Cannot resolve host: {host}"}), 400

    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(scan_port, ip, p, timeout, grab_banner) for p in ports]
        for f in futures:
            r = f.result()
            if r:
                results.append(r)

    return jsonify({"ip": ip, "results": sorted(results, key=lambda x: x["port"])})

if __name__ == "__main__":
    app.run(port=5000)