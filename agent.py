import socket
import socketserver
import sys
from dataclasses import asdict, dataclass
from typing import Callable, Tuple

EVENT_PORT = 2968
AGENT_PORT = 2968
AGENT_GROUP = "239.255.255.253"


def _srvloc_str_to_bytes(s: str) -> bytearray:
    """
    Note: will change the passed in bytearray
    """
    s_encoded = s.encode("utf-8")
    pkt = bytearray(len(s_encoded).to_bytes(2))
    pkt += s_encoded
    return pkt


def _srvloc_string_from_bytes(data: bytes, pos: int) -> (int, str):
    length = int.from_bytes(data[pos : pos + 2])
    pos += 2
    rawstr = data[pos : pos + length]
    pos += length
    return pos, rawstr.decode("utf-8")


@dataclass
class SrvlocHeader:
    version: int = 2
    function_id: int = 0
    length: int = 0
    overflow: bool = False
    fresh: bool = False
    mcast: bool = False
    next_ext_offset: int = 0
    xid: int = 0
    language_tag: str = ""

    def to_bytes(self) -> bytearray:
        pkt = bytearray(12)
        pkt[0] = self.version & 0xFF
        pkt[1] = self.function_id & 0xFF
        pkt[2 : 2 + 3] = self.length.to_bytes(3)
        pkt[5] = 0x80 if self.overflow else 0
        pkt[5] |= 0x40 if self.fresh else 0
        pkt[5] |= 0x20 if self.mcast else 0
        pkt[7 : 7 + 3] = self.next_ext_offset.to_bytes(3)
        pkt[10 : 10 + 2] = self.xid.to_bytes(2)
        pkt.extend(_srvloc_str_to_bytes(self.language_tag))
        return pkt

    def fix_pkt_length(self, pkt) -> None:
        self.length = len(pkt)
        pkt[2 : 2 + 3] = self.length.to_bytes(3)


@dataclass
class AttrRqst(SrvlocHeader):
    prlist: str = ""
    url: str = ""
    scope_list: str = ""
    tag_list: str = ""
    slp_spi: str = ""

    def __post_init__(self):
        self.function_id = 6


@dataclass
class AttrRepl(SrvlocHeader):
    error_code: int = 0
    attr_list: str = ""
    # no authentication

    def __post_init__(self):
        self.function_id = 7

    def to_bytes(self) -> bytearray:
        pkt = super().to_bytes()
        pkt.extend(self.error_code.to_bytes(2))
        pkt.extend(_srvloc_str_to_bytes(self.attr_list))
        self.fix_pkt_length(pkt)
        return pkt


def srvloc_message_factory(function_id: int) -> SrvlocHeader:
    if function_id == 6:
        return AttrRqst()
    else:
        return SrvlocHeader(function_id=function_id)


class SrvlocParseError(RuntimeError):
    pass


def parse_srvloc(data: bytes, pos: int = 0) -> (int, SrvlocHeader):
    try:
        version = data[pos + 0]
        if version != 2:
            raise SrvlocParseError("version != 2")
        pos += 1

        function_id = data[pos]
        pos += 1

        msg = srvloc_message_factory(function_id)

        msg.length = int.from_bytes(data[pos : pos + 3])
        # if msg.length != len(data):
        #    raise SrvlocParseError(f"length error ({len(data)} != {msg.length}")
        pos += 3

        msg.overflow = True if data[pos] & 0x80 == 0x80 else False
        msg.fresh = True if data[pos] & 0x40 == 0x40 else False
        msg.mcast = True if data[pos] & 0x20 == 0x20 else False
        pos += 2

        msg.next_ext_offset = int.from_bytes(data[pos : pos + 3])
        pos += 3

        msg.xid = int.from_bytes(data[pos : pos + 2])
        pos += 2

        pos, msg.language_tag = _srvloc_string_from_bytes(data, pos)

        if isinstance(msg, AttrRqst):
            pos, msg.prlist = _srvloc_string_from_bytes(data, pos)
            pos, msg.url = _srvloc_string_from_bytes(data, pos)
            pos, msg.scope_list = _srvloc_string_from_bytes(data, pos)
            pos, msg.tag_list = _srvloc_string_from_bytes(data, pos)
            pos, msg.slp_spi = _srvloc_string_from_bytes(data, pos)

        return pos, msg

    except IndexError:
        raise SrvlocParseError("short data")
    except UnicodeError:
        raise SrvlocParseError("invalid UTF-8")


class Agent(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        pos, rqst = parse_srvloc(data)
        print(f"{self.client_address[0]} wrote: {rqst}")

        if (
            isinstance(rqst, AttrRqst)
            and not rqst.overflow
            and rqst.mcast
            and rqst.url == "service:NetScanMonitor-agent"
        ):
            repl = AttrRepl()
            repl.xid = rqst.xid
            repl.language_tag = rqst.language_tag
            repl.error_code = 0
            repl.attr_list = f"(ClientName={server.myname}),(IPAddress={server.myip}),(EventPort={EVENT_PORT})"

            data = repl.to_bytes()
            print(f"reply: {repl}")
            server.rspsock.sendto(data, self.client_address)


class MCASTServer(socketserver.UDPServer):
    def __init__(
        self,
        myname: str,
        server_address: Tuple[str, str, int],
        RequestHandlerClass: Callable[..., socketserver.BaseRequestHandler],
        bind_and_activate: bool = True,
    ) -> None:
        super().__init__(
            ("", server_address[2]), RequestHandlerClass, bind_and_activate
        )
        mreq = socket.inet_aton(server_address[1]) + socket.inet_aton(server_address[0])
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.myip = server_address[0]
        self.myname = myname
        self.rspsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        super().__exit__(exc_type, exc_value, traceback)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: agent <name> <local interface IP>")
        sys.exit(1)

    try:
        with MCASTServer(
            sys.argv[1], (sys.argv[2], AGENT_GROUP, AGENT_PORT), Agent
        ) as server:
            server.serve_forever()

    except KeyboardInterrupt:
        pass
