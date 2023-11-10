import binascii
import http.server
import subprocess
import xml.etree.ElementTree as ET

import defusedxml.ElementTree as dET

EVENT_PORT = 2968

ENV_TAG = "{http://www.w3.org/2003/05/soap-envelope}Envelope"
PARAMS_PATH = "./{http://www.w3.org/2003/05/soap-envelope}Body/{http://schema.epson.net/EpsonNet/Scan/2004/pushscan}PushScan/*"

RESPONSE_OK = """<?xml version="1.0" ?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <p:PushScanResponse xmlns:p="http://schema.epson.net/EpsonNet/Scan/2004/pushscan">
      <StatusOut>OK</StatusOut>
    </p:PushScanResponse>
  </s:Body>
</s:Envelope>"""


class InvalidSOAPFormat(Exception):
    pass


class InvalidSOAPParameter(Exception):
    pass


def ip_fromhex(hip: str) -> str:
    if len(hip) != 8:
        raise InvalidSOAPParameter
    bip = binascii.unhexlify(hip)
    return f"{bip[0]}.{bip[1]}.{bip[2]}.{bip[3]}"


def get_nsb_args(content: str) -> (str, str, str):
    pid = ip = button = None

    envelope = dET.fromstring(content)
    if envelope.tag == ENV_TAG:
        call = envelope.findall(PARAMS_PATH)

        for c in call:
            if c.tag == "ProductNameIn":
                pid = c.text
            elif c.tag == "IPAddressIn":
                ip = ip_fromhex(c.text)
            elif c.tag == "PushScanIDIn":
                button = c.text
            else:
                raise InvalidSOAPParameter

    else:
        raise InvalidSOAPFormat

    return pid, ip, button


class NSBServer(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if (
            self.path != "/PushScan"
            or self.headers.get_content_type() != "application/octet-stream"
        ):
            self.send_error(400)
            return

        xuid = self.headers.get("x-uid")
        xuid = int(xuid) if xuid is not None else 0
        clength = self.headers.get("content-length")
        clength = int(clength) if clength is not None else 0

        if xuid < 1 or clength < 1 or clength > 4096:
            self.send_error(400)
            return

        content = self.rfile.read(clength)

        try:
            pid, ip, button = get_nsb_args(content)
        except (InvalidSOAPFormat, InvalidSOAPParameter) as e:
            self.log_message(f"SOAP error {e}")
            self.send_error(400)
            return

        self.log_message(f"[{xuid}] Product {pid} at {ip}: button {button}")

        clength = len(RESPONSE_OK)
        self.send_response_only(200)
        self.send_header("Server", "Epson Net Scan Monitor/2.0")
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", clength)
        self.send_header("x-protocol-name", "Epson Network Service Protocol")
        self.send_header("x-protocol-version", "2.00")
        self.send_header("x-uid", str(xuid))
        self.send_header("x-status", "0001")
        self.end_headers()
        self.wfile.write(RESPONSE_OK.encode("utf-8"))
        self.log_request(200, clength)

        subprocess.Popen(
            [
                "/usr/bin/scanimage",
                f"--device-name=epsonscan2:networkscanner:esci2:network:{ip}",
                "--mode=Color",
                "--transfer-format=no",
                "--resolution=300",
                "--scan-area=A4",
                "--output-file=/tmp/testscan.png",
            ]
        )

        return


if __name__ == "__main__":
    nsb_server = http.server.HTTPServer(("", EVENT_PORT), NSBServer)

    try:
        nsb_server.serve_forever()
    except KeyboardInterrupt:
        pass

    nsb_server.server_close()
