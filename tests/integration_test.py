#!/usr/bin/env python3
"""Integration tests for chukei-dns binary.

Starts the DNS server on a high port, sends raw DNS queries via TCP and UDP,
and verifies responses are correct. No external DNS tools required.
"""

import os
import signal
import socket
import struct
import subprocess
import sys
import time

# Configuration
DNS_IP = "127.0.0.1"
DNS_PORT = 15353  # High port to avoid needing root
BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "bin", "main")
ZONES_FILE = os.path.join(os.path.dirname(__file__), "..", "zones.json")
TIMEOUT = 2  # seconds per query
STARTUP_WAIT = 1  # seconds to wait for server startup
REDIRECT_IPV4 = "127.0.0.1"
REDIRECT_IPV6 = "0000:0000:0000:0000:0000:0000:0000:0001"

# DNS type constants
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_SRV = 33
QTYPE_ANY = 255


class DnsQuery:
    """Build a raw DNS query packet."""

    @staticmethod
    def build(domain, qtype=1, qclass=1, txn_id=0x1234, rd=True):
        """Build a DNS query for the given domain."""
        flags = 0x0100 if rd else 0x0000
        header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

        question = b""
        for label in domain.split("."):
            if label:
                question += struct.pack("B", len(label)) + label.encode()
        question += b"\x00"
        question += struct.pack("!HH", qtype, qclass)

        return header + question

    @staticmethod
    def build_edns0(domain, qtype=1, txn_id=0x1234, qclass=1, udp_payload=4096, version=0, do_bit=False, options=None):
        """Build a DNS query with EDNS0 OPT record (arcount=1)."""
        flags = 0x0100
        header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 1)

        question = b""
        for label in domain.split("."):
            if label:
                question += struct.pack("B", len(label)) + label.encode()
        question += b"\x00"
        question += struct.pack("!HH", qtype, qclass)

        if options is None:
            options = []

        ttl = (version << 16) | (0x8000 if do_bit else 0)
        rdata = b""
        for code, data in options:
            rdata += struct.pack("!HH", code, len(data)) + data

        opt = b"\x00" + struct.pack("!HHI", 41, udp_payload, ttl)
        opt += struct.pack("!H", len(rdata)) + rdata
        return header + question + opt


def parse_dns_name(data, offset):
    """Parse a DNS name from wire format, handling compression pointers.
    Returns (name_string, new_offset)."""
    labels = []
    jumped = False
    saved_offset = None

    while offset < len(data):
        length = data[offset]

        if length == 0:
            if not jumped:
                offset += 1
            else:
                offset = saved_offset
            return ".".join(labels) + "." if labels else ".", offset

        # Compression pointer (top 2 bits = 11)
        if (length & 0xC0) == 0xC0:
            if not jumped:
                saved_offset = offset + 2
                jumped = True
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            continue

        offset += 1
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    return ".".join(labels) + ".", offset


class DnsAnswer:
    """A parsed DNS answer record."""
    def __init__(self, name, rtype, rclass, ttl, rdlength, rdata_offset, raw_data):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata_offset = rdata_offset
        self.raw_data = raw_data

    def rdata_bytes(self):
        return self.raw_data[self.rdata_offset:self.rdata_offset + self.rdlength]

    def as_ipv4(self):
        """Decode A record rdata as IPv4 string."""
        rd = self.rdata_bytes()
        if len(rd) != 4:
            return None
        return ".".join(str(b) for b in rd)

    def as_ipv6(self):
        """Decode AAAA record rdata as IPv6 string."""
        rd = self.rdata_bytes()
        if len(rd) != 16:
            return None
        groups = [f"{rd[i]:02x}{rd[i+1]:02x}" for i in range(0, 16, 2)]
        # Simplified: just join with colons (no :: compression)
        return ":".join(groups)

    def as_domain(self):
        """Decode CNAME/NS/PTR rdata as domain name."""
        name, _ = parse_dns_name(self.raw_data, self.rdata_offset)
        return name


class DnsOpt:
    """Parsed EDNS0 OPT pseudo-record from a response."""
    def __init__(self, udp_payload_size, extended_rcode, version, do_bit, z, options):
        self.udp_payload_size = udp_payload_size
        self.extended_rcode = extended_rcode
        self.version = version
        self.do_bit = do_bit
        self.z = z
        self.options = options


class DnsResponse:
    """Parse a raw DNS response packet with full answer section."""

    def __init__(self, data):
        self.data = data
        if len(data) < 12:
            raise ValueError(f"Response too short: {len(data)} bytes")

        self.txn_id, self.flags, self.qdcount, self.ancount, \
            self.nscount, self.arcount = struct.unpack("!HHHHHH", data[:12])

        self.qr = (self.flags >> 15) & 1
        self.opcode = (self.flags >> 11) & 0xF
        self.aa = (self.flags >> 10) & 1
        self.tc = (self.flags >> 9) & 1
        self.rd = (self.flags >> 8) & 1
        self.ra = (self.flags >> 7) & 1
        self.rcode = self.flags & 0xF

        # Parse question section to find answer section offset
        self.answers = []
        self.opt = None
        offset = 12
        try:
            # Skip question section
            for _ in range(self.qdcount):
                _, offset = parse_dns_name(data, offset)
                offset += 4  # QTYPE + QCLASS

            # Parse answer section
            for _ in range(self.ancount):
                name, offset = parse_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                ans = DnsAnswer(name, rtype, rclass, ttl, rdlength, offset, data)
                self.answers.append(ans)
                offset += rdlength

            # Parse additional section to expose OPT pseudo-records.
            self.opt = None
            for _ in range(self.arcount):
                name, offset = parse_dns_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                if rtype == 41 and self.opt is None:
                    extended_rcode = (ttl >> 24) & 0xFF
                    version = (ttl >> 16) & 0xFF
                    do_bit = ((ttl >> 15) & 0x1) != 0
                    z = ttl & 0x7FFF
                    options = []
                    end = offset + rdlength
                    while offset + 4 <= end:
                        code, length = struct.unpack("!HH", data[offset:offset + 4])
                        offset += 4
                        value = data[offset:offset + length]
                        offset += length
                        options.append((code, value))
                    self.opt = DnsOpt(rclass, extended_rcode, version, do_bit, z, options)
                else:
                    offset += rdlength
        except (struct.error, IndexError):
            pass  # Partial parse is OK for error responses

    def get_answers_by_type(self, rtype):
        """Return all answers matching a given record type."""
        return [a for a in self.answers if a.rtype == rtype]


def send_query(query_data, ip=DNS_IP, port=DNS_PORT):
    """Send a DNS query and return the parsed response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(query_data, (ip, port))
        data, _ = sock.recvfrom(4096)
        return DnsResponse(data)
    finally:
        sock.close()


def send_tcp_query(query_data, ip=DNS_IP, port=DNS_PORT):
    """Send a DNS query over TCP (with 2-byte length prefix) and return the parsed response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((ip, port))
        # Send with 2-byte length prefix per RFC 1035 §4.2.2
        length_prefix = struct.pack("!H", len(query_data))
        sock.sendall(length_prefix + query_data)
        # Read 2-byte length prefix of response
        resp_len_data = b""
        while len(resp_len_data) < 2:
            chunk = sock.recv(2 - len(resp_len_data))
            if not chunk:
                raise ConnectionError("TCP connection closed before response length received")
            resp_len_data += chunk
        resp_len = struct.unpack("!H", resp_len_data)[0]
        # Read the full response
        resp_data = b""
        while len(resp_data) < resp_len:
            chunk = sock.recv(resp_len - len(resp_data))
            if not chunk:
                raise ConnectionError("TCP connection closed before full response received")
            resp_data += chunk
        return DnsResponse(resp_data)
    finally:
        sock.close()


class TestResults:
    """Track test results."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.failures = []

    def ok(self, name):
        self.passed += 1
        print(f"  [PASS] {name}")

    def fail(self, name, reason):
        self.failed += 1
        self.failures.append(f"{name}: {reason}")
        print(f"  [FAIL] {name}: {reason}")

    def summary(self):
        total = self.passed + self.failed
        print(f"========================================")
        print(f"Results: {self.passed} passed, {self.failed} failed, {total} total")
        if self.failures:
            print(f"\nFailures:")
            for f in self.failures:
                print(f"  - {f}")
        return 1 if self.failed > 0 else 0


def assert_eq(results, name, actual, expected, field=""):
    """Assert equality, recording pass/fail."""
    if actual != expected:
        detail = f"{field}: expected {expected}, got {actual}" if field else f"expected {expected}, got {actual}"
        results.fail(name, detail)
        return False
    return True


def run_tests(results):
    """Run all integration tests."""
    return run_tests_with_port(results, DNS_PORT)


def run_tests_with_port(results, port):
    """Run all integration tests against the given port."""

    def sq(data):
        return send_query(data, DNS_IP, port)

    # ========================================================================
    # A RECORD TESTS
    # ========================================================================

    # --- A record: root domain returns 0.0.0.0 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x1001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_root_domain", resp.txn_id, 0x1001, "txn_id")
        ok &= assert_eq(results, "udp_a_root_domain", resp.qr, 1, "QR")
        ok &= assert_eq(results, "udp_a_root_domain", resp.rd, 1, "RD")
        ok &= assert_eq(results, "udp_a_root_domain", resp.ra, 1, "RA")
        ok &= assert_eq(results, "udp_a_root_domain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_root_domain", resp.qdcount, 1, "QDCOUNT")
        ok &= assert_eq(results, "udp_a_root_domain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            a = resp.answers[0]
            ok &= assert_eq(results, "udp_a_root_domain", a.rtype, QTYPE_A, "answer type")
            ok &= assert_eq(results, "udp_a_root_domain", a.as_ipv4(), "0.0.0.0", "IP")
            ok &= assert_eq(results, "udp_a_root_domain", a.ttl, 3600, "TTL")
            ok &= assert_eq(results, "udp_a_root_domain", a.rclass, 1, "CLASS")
        else:
            ok = False
            results.fail("udp_a_root_domain", "no answer records")
        if ok:
            results.ok("udp_a_root_domain")
    except Exception as e:
        results.fail("udp_a_root_domain", str(e))

    # --- A record: wildcard subdomain ---
    try:
        pkt = DnsQuery.build("random.playstation.com", qtype=QTYPE_A, txn_id=0x1002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_a_wildcard", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_a_wildcard")
    except Exception as e:
        results.fail("udp_a_wildcard", str(e))

    # --- A record: specific subdomain (www.playstation.com -> {{SELF}} = 127.0.0.1) ---
    try:
        pkt = DnsQuery.build("www.playstation.com", qtype=QTYPE_A, txn_id=0x1003)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_www_subdomain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_www_subdomain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_a_www_subdomain", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_a_www_subdomain")
    except Exception as e:
        results.fail("udp_a_www_subdomain", str(e))

    # --- A record: root domain of another zone (nintendo.net) ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_A, txn_id=0x1004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_nintendo_root", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_nintendo_root", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_a_nintendo_root", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_a_nintendo_root")
    except Exception as e:
        results.fail("udp_a_nintendo_root", str(e))

    # --- A record: deep wildcard subdomain (a.b.c.playstation.com) ---
    try:
        pkt = DnsQuery.build("a.b.c.playstation.com", qtype=QTYPE_A, txn_id=0x1005)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_deep_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_deep_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_a_deep_wildcard", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_a_deep_wildcard")
    except Exception as e:
        results.fail("udp_a_deep_wildcard", str(e))

    # --- A record: regex subdomain (ctest.cdn.nintendo.net -> {{SELF}} = 127.0.0.1) ---
    try:
        pkt = DnsQuery.build("ctest.cdn.nintendo.net", qtype=QTYPE_A, txn_id=0x1006)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_regex_subdomain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_regex_subdomain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_a_regex_subdomain", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_a_regex_subdomain")
    except Exception as e:
        results.fail("udp_a_regex_subdomain", str(e))

    # --- A record: complex regex (djp01.ps4.update.playstation.net -> {{SELF}} = 127.0.0.1) ---
    try:
        pkt = DnsQuery.build("djp01.ps4.update.playstation.net", qtype=QTYPE_A, txn_id=0x1007)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_a_complex_regex", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_a_complex_regex", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_a_complex_regex", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_a_complex_regex")
    except Exception as e:
        results.fail("udp_a_complex_regex", str(e))

    # ========================================================================
    # AAAA RECORD TESTS
    # ========================================================================

    # --- AAAA record: root domain returns :: ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0x2001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_aaaa_root_domain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_aaaa_root_domain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            a = resp.answers[0]
            ok &= assert_eq(results, "udp_aaaa_root_domain", a.rtype, QTYPE_AAAA, "answer type")
            ok &= assert_eq(results, "udp_aaaa_root_domain", a.as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "IPv6")
            ok &= assert_eq(results, "udp_aaaa_root_domain", a.rdlength, 16, "RDLENGTH")
        else:
            ok = False
        if ok:
            results.ok("udp_aaaa_root_domain")
    except Exception as e:
        results.fail("udp_aaaa_root_domain", str(e))

    # --- AAAA record: wildcard subdomain ---
    try:
        pkt = DnsQuery.build("sub.playstation.com", qtype=QTYPE_AAAA, txn_id=0x2002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_aaaa_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_aaaa_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_aaaa_wildcard", resp.answers[0].as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "IPv6")
        else:
            ok = False
        if ok:
            results.ok("udp_aaaa_wildcard")
    except Exception as e:
        results.fail("udp_aaaa_wildcard", str(e))

    # ========================================================================
    # CNAME RECORD TESTS
    # ========================================================================

    # --- CNAME: A query for CNAME subdomain returns CNAME answer ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_cname_a_query", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 1)
        if not (resp.ancount >= 1):
            results.fail("udp_cname_a_query", f"ANCOUNT={resp.ancount}, expected >= 1")
        else:
            # First answer should be CNAME
            cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
            if cname_answers:
                ok &= assert_eq(results, "udp_cname_a_query", cname_answers[0].as_domain(), "b0.ww.np.dl.playstation.net.edgesuite.net.", "CNAME target")
            else:
                ok = False
                results.fail("udp_cname_a_query", "no CNAME answer record found")
        if ok:
            results.ok("udp_cname_a_query")
    except Exception as e:
        results.fail("udp_cname_a_query", str(e))

    # --- CNAME: different subdomain (gs.ww.np.dl) ---
    try:
        pkt = DnsQuery.build("gs.ww.np.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_cname_gs_subdomain", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "udp_cname_gs_subdomain", cname_answers[0].as_domain(), "gs.ww.np.dl.playstation.net.edgesuite.net.", "CNAME target")
        else:
            ok = False
            results.fail("udp_cname_gs_subdomain", "no CNAME")
        if ok:
            results.ok("udp_cname_gs_subdomain")
    except Exception as e:
        results.fail("udp_cname_gs_subdomain", str(e))

    # --- CNAME: gs2.ww.prod.dl -> gs2.ww.prod.dl.playstation.net.edgesuite.net. ---
    try:
        pkt = DnsQuery.build("gs2.ww.prod.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3003)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_cname_gs2_subdomain", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "udp_cname_gs2_subdomain", cname_answers[0].as_domain(), "gs2.ww.prod.dl.playstation.net.edgesuite.net.", "target")
        else:
            ok = False
            results.fail("udp_cname_gs2_subdomain", "no CNAME")
        if ok:
            results.ok("udp_cname_gs2_subdomain")
    except Exception as e:
        results.fail("udp_cname_gs2_subdomain", str(e))

    # --- CNAME: gst.prod.dl -> gst.prod.dl.playstation.net.edgesuite.net. ---
    try:
        pkt = DnsQuery.build("gst.prod.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_cname_gst_subdomain", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "udp_cname_gst_subdomain", cname_answers[0].as_domain(), "gst.prod.dl.playstation.net.edgesuite.net.", "target")
        else:
            ok = False
            results.fail("udp_cname_gst_subdomain", "no CNAME")
        if ok:
            results.ok("udp_cname_gst_subdomain")
    except Exception as e:
        results.fail("udp_cname_gst_subdomain", str(e))

    # --- CNAME: querying CNAME type directly should return the CNAME record ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_CNAME, txn_id=0x3005)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_cname_direct_query", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_cname_direct_query", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_cname_direct_query", resp.answers[0].rtype, QTYPE_CNAME, "answer type")
            ok &= assert_eq(results, "udp_cname_direct_query", resp.answers[0].as_domain(), "b0.ww.np.dl.playstation.net.edgesuite.net.", "target")
        else:
            ok = False
        if ok:
            results.ok("udp_cname_direct_query")
    except Exception as e:
        results.fail("udp_cname_direct_query", str(e))

    # --- CNAME query for non-CNAME subdomain in same zone falls through to A/AAAA ---
    try:
        # "manuals.playstation.net" has A/AAAA but no CNAME
        pkt = DnsQuery.build("manuals.playstation.net", qtype=QTYPE_A, txn_id=0x3006)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_no_cname_fallthrough", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_no_cname_fallthrough", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_no_cname_fallthrough", resp.answers[0].rtype, QTYPE_A, "answer type")
            ok &= assert_eq(results, "udp_no_cname_fallthrough", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_no_cname_fallthrough")
    except Exception as e:
        results.fail("udp_no_cname_fallthrough", str(e))

    # ========================================================================
    # BLOCKED DOMAIN TESTS ({{BLOCKED}} -> NXDOMAIN)
    # ========================================================================

    # --- Blocked domain: A query -> NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_A, txn_id=0x4001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_blocked_nxdomain", resp.rcode, 3, "RCODE (NXDOMAIN)")
        ok &= assert_eq(results, "udp_blocked_nxdomain", resp.ancount, 0, "ANCOUNT")
        ok &= assert_eq(results, "udp_blocked_nxdomain", resp.qr, 1, "QR")
        if ok:
            results.ok("udp_blocked_nxdomain")
    except Exception as e:
        results.fail("udp_blocked_nxdomain", str(e))

    # --- Blocked domain: AAAA query -> NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_AAAA, txn_id=0x4002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_blocked_aaaa_nxdomain", resp.rcode, 3, "RCODE")
        ok &= assert_eq(results, "udp_blocked_aaaa_nxdomain", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("udp_blocked_aaaa_nxdomain")
    except Exception as e:
        results.fail("udp_blocked_aaaa_nxdomain", str(e))

    # --- Blocked domain: subdomain also blocked ---
    try:
        pkt = DnsQuery.build("www.nintendo.com", qtype=QTYPE_A, txn_id=0x4003)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_blocked_subdomain", resp.rcode, 3, "RCODE (NXDOMAIN)")
        ok &= assert_eq(results, "udp_blocked_subdomain", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("udp_blocked_subdomain")
    except Exception as e:
        results.fail("udp_blocked_subdomain", str(e))

    # --- Multiple different blocked domains ---
    try:
        blocked_domains = [
            "scea.com", "playstation.org", "sie-rd.com",
            "sonyentertainmentnetwork.com", "nintendoswitch.com",
        ]
        all_ok = True
        for domain in blocked_domains:
            pkt = DnsQuery.build(domain, qtype=QTYPE_A, txn_id=0x4010)
            resp = sq(pkt)
            if resp.rcode != 3:
                all_ok = False
                results.fail("udp_blocked_multiple", f"{domain}: RCODE={resp.rcode}, expected 3")
                break
        if all_ok:
            results.ok("udp_blocked_multiple")
    except Exception as e:
        results.fail("udp_blocked_multiple", str(e))

    # ========================================================================
    # ANY QUERY TESTS
    # ========================================================================

    # --- ANY query: root domain returns A + AAAA ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0x5001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_any_root_multi", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("udp_any_root_multi", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            a_records = resp.get_answers_by_type(QTYPE_A)
            aaaa_records = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_records) >= 1)
            ok &= (len(aaaa_records) >= 1)
            if a_records:
                ok &= assert_eq(results, "udp_any_root_multi", a_records[0].as_ipv4(), "0.0.0.0", "A IP")
            if aaaa_records:
                ok &= assert_eq(results, "udp_any_root_multi", aaaa_records[0].as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "AAAA IP")
            if ok:
                results.ok("udp_any_root_multi")
    except Exception as e:
        results.fail("udp_any_root_multi", str(e))

    # --- ANY query: wildcard subdomain ---
    try:
        pkt = DnsQuery.build("anything.playstation.com", qtype=QTYPE_ANY, txn_id=0x5002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_any_wildcard_multi", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("udp_any_wildcard_multi", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            a_records = resp.get_answers_by_type(QTYPE_A)
            aaaa_records = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_records) >= 1)
            ok &= (len(aaaa_records) >= 1)
            if ok:
                results.ok("udp_any_wildcard_multi")
    except Exception as e:
        results.fail("udp_any_wildcard_multi", str(e))

    # --- ANY query: domain with CNAME records includes CNAME in response ---
    try:
        # playstation.net has A + AAAA + CNAME. CNAME subdomain test:
        # Root has A, AAAA; CNAME is only for subdomains.
        pkt = DnsQuery.build("playstation.net", qtype=QTYPE_ANY, txn_id=0x5003)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_any_with_cname_zone", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("udp_any_with_cname_zone", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            # Root domain should have A + AAAA (CNAME entries are for subdomains only)
            a_recs = resp.get_answers_by_type(QTYPE_A)
            aaaa_recs = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_recs) >= 1)
            ok &= (len(aaaa_recs) >= 1)
            if ok:
                results.ok("udp_any_with_cname_zone")
    except Exception as e:
        results.fail("udp_any_with_cname_zone", str(e))

    # --- ANY query: blocked domain returns NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_ANY, txn_id=0x5004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_any_blocked", resp.rcode, 3, "RCODE (NXDOMAIN)")
        ok &= assert_eq(results, "udp_any_blocked", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("udp_any_blocked")
    except Exception as e:
        results.fail("udp_any_blocked", str(e))

    # ========================================================================
    # HEADER FLAGS / PROTOCOL TESTS
    # ========================================================================

    # --- Transaction ID preserved ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xBEEF)
        resp = sq(pkt)
        if assert_eq(results, "udp_txn_id_preserved", resp.txn_id, 0xBEEF, "txn_id"):
            results.ok("udp_txn_id_preserved")
    except Exception as e:
        results.fail("udp_txn_id_preserved", str(e))

    # --- RD bit echoed (RD=1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6001, rd=True)
        resp = sq(pkt)
        if assert_eq(results, "udp_rd_echoed_1", resp.rd, 1, "RD"):
            results.ok("udp_rd_echoed_1")
    except Exception as e:
        results.fail("udp_rd_echoed_1", str(e))

    # --- RD bit echoed (RD=0) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6002, rd=False)
        resp = sq(pkt)
        if assert_eq(results, "udp_rd_echoed_0", resp.rd, 0, "RD"):
            results.ok("udp_rd_echoed_0")
    except Exception as e:
        results.fail("udp_rd_echoed_0", str(e))

    # --- QR bit is 1 (response) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6003)
        resp = sq(pkt)
        if assert_eq(results, "udp_qr_is_response", resp.qr, 1, "QR"):
            results.ok("udp_qr_is_response")
    except Exception as e:
        results.fail("udp_qr_is_response", str(e))

    # --- RA bit is 1 (recursion available) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6004)
        resp = sq(pkt)
        if assert_eq(results, "udp_ra_set", resp.ra, 1, "RA"):
            results.ok("udp_ra_set")
    except Exception as e:
        results.fail("udp_ra_set", str(e))

    # --- TC bit is 0 (not truncated) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6005)
        resp = sq(pkt)
        if assert_eq(results, "udp_tc_not_set", resp.tc, 0, "TC"):
            results.ok("udp_tc_not_set")
    except Exception as e:
        results.fail("udp_tc_not_set", str(e))

    # --- OPCODE echoed as 0 (standard query) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6006)
        resp = sq(pkt)
        if assert_eq(results, "udp_opcode_standard", resp.opcode, 0, "OPCODE"):
            results.ok("udp_opcode_standard")
    except Exception as e:
        results.fail("udp_opcode_standard", str(e))

    # --- QDCOUNT is 1 in response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6007)
        resp = sq(pkt)
        if assert_eq(results, "udp_qdcount_one", resp.qdcount, 1, "QDCOUNT"):
            results.ok("udp_qdcount_one")
    except Exception as e:
        results.fail("udp_qdcount_one", str(e))

    # ========================================================================
    # EDNS0 TESTS
    # ========================================================================

    # --- EDNS0 query accepted ---
    try:
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_edns0_accepted", resp.txn_id, 0x7001, "txn_id")
        ok &= assert_eq(results, "udp_edns0_accepted", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_edns0_accepted", resp.ancount, 1, "ANCOUNT")
        ok &= assert_eq(results, "udp_edns0_accepted", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "udp_edns0_accepted", resp.opt.version, 0, "EDNS version")
            ok &= assert_eq(results, "udp_edns0_accepted", resp.opt.udp_payload_size, 1232, "UDP payload size")
        else:
            ok = False
            results.fail("udp_edns0_accepted", "no OPT record parsed")
        if ok:
            results.ok("udp_edns0_accepted")
    except Exception as e:
        results.fail("udp_edns0_accepted", str(e))

    # --- EDNS0 query with unknown option ignored ---
    try:
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7005, options=[(65001, b"ignore")])
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_edns0_unknown_option", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_edns0_unknown_option", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "udp_edns0_unknown_option", len(resp.opt.options), 0, "unknown option ignored")
        else:
            ok = False
            results.fail("udp_edns0_unknown_option", "no OPT record parsed")
        if ok:
            results.ok("udp_edns0_unknown_option")
    except Exception as e:
        results.fail("udp_edns0_unknown_option", str(e))

    # --- EDNS0 query with COOKIE option echoed ---
    try:
        cookie = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7003, options=[(10, cookie)])
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_edns0_cookie_echo", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_edns0_cookie_echo", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "udp_edns0_cookie_echo", resp.opt.version, 0, "EDNS version")
            ok &= assert_eq(results, "udp_edns0_cookie_echo", resp.opt.options[0][0], 10, "OPTION code")
            ok &= assert_eq(results, "udp_edns0_cookie_echo", resp.opt.options[0][1], cookie, "OPTION data")
        else:
            ok = False
            results.fail("udp_edns0_cookie_echo", "no OPT record parsed")
        if ok:
            results.ok("udp_edns0_cookie_echo")
    except Exception as e:
        results.fail("udp_edns0_cookie_echo", str(e))

    # --- EDNS0 query with BADVERS version ---
    try:
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7004, version=1)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_edns0_badvers", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_edns0_badvers", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "udp_edns0_badvers", resp.opt.extended_rcode, 1, "Extended RCODE")
            ok &= assert_eq(results, "udp_edns0_badvers", resp.opt.version, 0, "Response EDNS version")
        else:
            ok = False
            results.fail("udp_edns0_badvers", "no OPT record parsed")
        if ok:
            results.ok("udp_edns0_badvers")
    except Exception as e:
        results.fail("udp_edns0_badvers", str(e))

    # --- EDNS0 query with AAAA ---
    try:
        pkt = DnsQuery.build_edns0("nintendo.net", qtype=QTYPE_AAAA, txn_id=0x7002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_edns0_aaaa", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_edns0_aaaa", resp.ancount, 1, "ANCOUNT")
        ok &= assert_eq(results, "udp_edns0_aaaa", resp.arcount, 1, "ARCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "udp_edns0_aaaa", resp.answers[0].rtype, QTYPE_AAAA, "type")
        else:
            ok = False
        if ok:
            results.ok("udp_edns0_aaaa")
    except Exception as e:
        results.fail("udp_edns0_aaaa", str(e))

    # ========================================================================
    # ERROR RESPONSE TESTS
    # ========================================================================

    # --- FORMERR: malformed packet (header only, no question) ---
    try:
        malformed = struct.pack("!HHHHHH", 0x8001, 0x0100, 1, 0, 0, 0)
        resp = sq(malformed)
        ok = True
        ok &= assert_eq(results, "udp_formerr_no_question", resp.txn_id, 0x8001, "txn_id")
        ok &= assert_eq(results, "udp_formerr_no_question", resp.qr, 1, "QR")
        ok &= assert_eq(results, "udp_formerr_no_question", resp.rcode, 1, "RCODE (FORMERR)")
        ok &= assert_eq(results, "udp_formerr_no_question", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("udp_formerr_no_question")
    except Exception as e:
        results.fail("udp_formerr_no_question", str(e))

    # --- NOTIMP: non-standard opcode ---
    try:
        flags = (2 << 11) | 0x0100  # OPCODE=2, RD=1
        header = struct.pack("!HHHHHH", 0x8002, flags, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00"
        question += struct.pack("!HH", 1, 1)
        pkt = header + question
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_notimp_opcode", resp.txn_id, 0x8002, "txn_id")
        ok &= assert_eq(results, "udp_notimp_opcode", resp.rcode, 4, "RCODE (NOTIMP)")
        ok &= assert_eq(results, "udp_notimp_opcode", resp.qr, 1, "QR")
        if ok:
            results.ok("udp_notimp_opcode")
    except Exception as e:
        results.fail("udp_notimp_opcode", str(e))

    # --- Server survives FORMERR and responds to next query ---
    try:
        malformed = struct.pack("!HHHHHH", 0x8003, 0x0100, 1, 0, 0, 0)
        try:
            sq(malformed)
        except socket.timeout:
            pass
        time.sleep(0.1)
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x8004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_survives_formerr", resp.txn_id, 0x8004, "txn_id")
        ok &= assert_eq(results, "udp_survives_formerr", resp.rcode, 0, "RCODE")
        if ok:
            results.ok("udp_survives_formerr")
    except Exception as e:
        results.fail("udp_survives_formerr", str(e))

    # ========================================================================
    # ANSWER SECTION DATA VALIDATION
    # ========================================================================

    # --- A record answer uses question pointer (0xC00C) for NAME ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x9001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_answer_uses_pointer", resp.rcode, 0, "RCODE")
        if resp.answers:
            # NAME field should reference the question name via a pointer
            ok &= assert_eq(results, "udp_answer_uses_pointer", resp.answers[0].name, "playstation.com.", "answer name")
        else:
            ok = False
        if ok:
            results.ok("udp_answer_uses_pointer")
    except Exception as e:
        results.fail("udp_answer_uses_pointer", str(e))

    # --- A record TTL is 3600 (default) ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_A, txn_id=0x9002)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "udp_ttl_default", resp.answers[0].ttl, 3600, "TTL")
        else:
            ok = False
        if ok:
            results.ok("udp_ttl_default")
    except Exception as e:
        results.fail("udp_ttl_default", str(e))

    # --- AAAA record: all 16 bytes are zeros for :: ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_AAAA, txn_id=0x9003)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            rdata = resp.answers[0].rdata_bytes()
            ok &= assert_eq(results, "udp_aaaa_all_zeros", len(rdata), 16, "RDLENGTH")
            ok &= assert_eq(results, "udp_aaaa_all_zeros", rdata, b"\x00" * 16, "IPv6 bytes")
        else:
            ok = False
        if ok:
            results.ok("udp_aaaa_all_zeros")
    except Exception as e:
        results.fail("udp_aaaa_all_zeros", str(e))

    # --- A record: RDATA is exactly 4 bytes of zeros for 0.0.0.0 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x9004)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            rdata = resp.answers[0].rdata_bytes()
            ok &= assert_eq(results, "udp_a_rdata_zero", len(rdata), 4, "RDLENGTH")
            ok &= assert_eq(results, "udp_a_rdata_zero", rdata, b"\x00\x00\x00\x00", "IPv4 bytes")
        else:
            ok = False
        if ok:
            results.ok("udp_a_rdata_zero")
    except Exception as e:
        results.fail("udp_a_rdata_zero", str(e))

    # --- Answer CLASS matches query CLASS (IN = 1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, qclass=1, txn_id=0x9005)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "udp_answer_class_in", resp.answers[0].rclass, 1, "CLASS")
        else:
            ok = False
        if ok:
            results.ok("udp_answer_class_in")
    except Exception as e:
        results.fail("udp_answer_class_in", str(e))

    # ========================================================================
    # MULTI-ZONE TESTS
    # ========================================================================

    # --- Different zones: nintendo.net A root ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_A, txn_id=0xA001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_zone_nintendo_net", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_zone_nintendo_net", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_zone_nintendo_net")
    except Exception as e:
        results.fail("udp_zone_nintendo_net", str(e))

    # --- Different zones: wii.com A root ---
    try:
        pkt = DnsQuery.build("wii.com", qtype=QTYPE_A, txn_id=0xA002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_zone_wii_com", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_zone_wii_com", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_zone_wii_com")
    except Exception as e:
        results.fail("udp_zone_wii_com", str(e))

    # --- Different zones: nintendowifi.net A root ---
    try:
        pkt = DnsQuery.build("nintendowifi.net", qtype=QTYPE_A, txn_id=0xA003)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_zone_nintendowifi", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_zone_nintendowifi", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_zone_nintendowifi")
    except Exception as e:
        results.fail("udp_zone_nintendowifi", str(e))

    # --- Zone-specific subdomains: conntest.nintendowifi.net ---
    try:
        pkt = DnsQuery.build("conntest.nintendowifi.net", qtype=QTYPE_A, txn_id=0xA004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_zone_conntest", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_zone_conntest", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_zone_conntest")
    except Exception as e:
        results.fail("udp_zone_conntest", str(e))

    # --- Zone-specific subdomains: cfh.wapp.wii.com ---
    try:
        pkt = DnsQuery.build("cfh.wapp.wii.com", qtype=QTYPE_A, txn_id=0xA005)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_zone_cfh_wapp", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_zone_cfh_wapp", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_zone_cfh_wapp")
    except Exception as e:
        results.fail("udp_zone_cfh_wapp", str(e))

    # ========================================================================
    # RAPID / STRESS TESTS
    # ========================================================================

    # --- Multiple rapid queries with different txn_ids ---
    try:
        all_ok = True
        for i in range(10):
            tid = 0xB000 + i
            pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=tid)
            resp = sq(pkt)
            if resp.txn_id != tid or resp.rcode != 0:
                all_ok = False
                results.fail("udp_rapid_queries", f"Failed on iteration {i}: txn_id=0x{resp.txn_id:04x}, rcode={resp.rcode}")
                break
        if all_ok:
            results.ok("udp_rapid_queries")
    except Exception as e:
        results.fail("udp_rapid_queries", str(e))

    # --- Rapid queries across different domains ---
    try:
        domains = [
            ("playstation.com", QTYPE_A, 0),
            ("nintendo.net", QTYPE_AAAA, 0),
            ("wii.com", QTYPE_A, 0),
            ("nintendo.com", QTYPE_A, 3),  # blocked -> NXDOMAIN
            ("playstation.net", QTYPE_A, 0),
        ]
        all_ok = True
        for i, (domain, qtype, expected_rcode) in enumerate(domains):
            tid = 0xB100 + i
            pkt = DnsQuery.build(domain, qtype=qtype, txn_id=tid)
            resp = sq(pkt)
            if resp.txn_id != tid:
                all_ok = False
                results.fail("udp_rapid_cross_domain", f"{domain}: txn_id mismatch")
                break
            if resp.rcode != expected_rcode:
                all_ok = False
                results.fail("udp_rapid_cross_domain", f"{domain}: rcode={resp.rcode}, expected {expected_rcode}")
                break
        if all_ok:
            results.ok("udp_rapid_cross_domain")
    except Exception as e:
        results.fail("udp_rapid_cross_domain", str(e))

    # ========================================================================
    # REGEX PATTERN TESTS
    # ========================================================================

    # --- Regex: fus01.ps5.update.playstation.net ---
    try:
        pkt = DnsQuery.build("fus01.ps5.update.playstation.net", qtype=QTYPE_A, txn_id=0xC001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_regex_fus01_ps5", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_regex_fus01_ps5", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_regex_fus01_ps5")
    except Exception as e:
        results.fail("udp_regex_fus01_ps5", str(e))

    # --- Regex: heu01.ps4.update.playstation.net ---
    try:
        pkt = DnsQuery.build("heu01.ps4.update.playstation.net", qtype=QTYPE_A, txn_id=0xC002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_regex_heu01_ps4", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_regex_heu01_ps4", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_regex_heu01_ps4")
    except Exception as e:
        results.fail("udp_regex_heu01_ps4", str(e))

    # --- Regex: get.net.playstation.net ---
    try:
        pkt = DnsQuery.build("get.net.playstation.net", qtype=QTYPE_A, txn_id=0xC003)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_regex_get_net", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_regex_get_net", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("udp_regex_get_net")
    except Exception as e:
        results.fail("udp_regex_get_net", str(e))

    # --- Regex: AAAA versions of regex subdomains ---
    try:
        pkt = DnsQuery.build("djp01.ps4.update.playstation.net", qtype=QTYPE_AAAA, txn_id=0xC004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_regex_aaaa", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "udp_regex_aaaa", resp.answers[0].rtype, QTYPE_AAAA, "type")
            ok &= assert_eq(results, "udp_regex_aaaa", resp.answers[0].as_ipv6(), REDIRECT_IPV6, "IPv6")
        else:
            ok = False
        if ok:
            results.ok("udp_regex_aaaa")
    except Exception as e:
        results.fail("udp_regex_aaaa", str(e))

    # ========================================================================
    # CNAME WITH AAAA QUERY
    # ========================================================================

    # --- CNAME returned for AAAA query too ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_AAAA, txn_id=0xD001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_cname_with_aaaa", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "udp_cname_with_aaaa", cname_answers[0].as_domain(), "b0.ww.np.dl.playstation.net.edgesuite.net.", "CNAME target")
        else:
            ok = False
            results.fail("udp_cname_with_aaaa", "no CNAME answer for AAAA query")
        if ok:
            results.ok("udp_cname_with_aaaa")
    except Exception as e:
        results.fail("udp_cname_with_aaaa", str(e))

    # ========================================================================
    # MULTI-ANSWER CONTENT VALIDATION
    # ========================================================================

    # --- ANY returns correct data in both A and AAAA records ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_ANY, txn_id=0xE001)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_any_data_validation", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("udp_any_data_validation", f"ANCOUNT={resp.ancount}")
        else:
            a_recs = resp.get_answers_by_type(QTYPE_A)
            aaaa_recs = resp.get_answers_by_type(QTYPE_AAAA)
            if a_recs:
                ok &= assert_eq(results, "udp_any_data_validation", a_recs[0].as_ipv4(), "0.0.0.0", "A data")
                ok &= assert_eq(results, "udp_any_data_validation", a_recs[0].ttl, 3600, "A TTL")
            else:
                ok = False
            if aaaa_recs:
                ok &= assert_eq(results, "udp_any_data_validation", aaaa_recs[0].rdata_bytes(), b"\x00" * 16, "AAAA bytes")
                ok &= assert_eq(results, "udp_any_data_validation", aaaa_recs[0].ttl, 3600, "AAAA TTL")
            else:
                ok = False
            if ok:
                results.ok("udp_any_data_validation")
    except Exception as e:
        results.fail("udp_any_data_validation", str(e))

    # --- Verify all answer records in ANY have CLASS=IN ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0xE002)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_any_class_check", resp.rcode, 0, "RCODE")
        for i, ans in enumerate(resp.answers):
            if ans.rclass != 1:
                ok = False
                results.fail("udp_any_class_check", f"answer[{i}] CLASS={ans.rclass}, expected 1")
                break
        if ok and resp.answers:
            results.ok("udp_any_class_check")
        elif not resp.answers:
            results.fail("udp_any_class_check", "no answers")
    except Exception as e:
        results.fail("udp_any_class_check", str(e))

    # ========================================================================
    # RFC COMPLIANCE: AA (Authoritative Answer) BIT - RFC 1035 §4.1.1
    # ========================================================================

    # --- AA=1 for authoritative A record response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF001)
        resp = sq(pkt)
        if assert_eq(results, "udp_aa_set_for_a", resp.aa, 1, "AA"):
            results.ok("udp_aa_set_for_a")
    except Exception as e:
        results.fail("udp_aa_set_for_a", str(e))

    # --- AA=1 for authoritative AAAA record response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0xF002)
        resp = sq(pkt)
        if assert_eq(results, "udp_aa_set_for_aaaa", resp.aa, 1, "AA"):
            results.ok("udp_aa_set_for_aaaa")
    except Exception as e:
        results.fail("udp_aa_set_for_aaaa", str(e))

    # --- AA=1 for authoritative CNAME response ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_CNAME, txn_id=0xF003)
        resp = sq(pkt)
        if assert_eq(results, "udp_aa_set_for_cname", resp.aa, 1, "AA"):
            results.ok("udp_aa_set_for_cname")
    except Exception as e:
        results.fail("udp_aa_set_for_cname", str(e))

    # --- AA=1 for blocked domain NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_A, txn_id=0xF004)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_aa_set_for_nxdomain", resp.rcode, 3, "RCODE")
        ok &= assert_eq(results, "udp_aa_set_for_nxdomain", resp.aa, 1, "AA")
        if ok:
            results.ok("udp_aa_set_for_nxdomain")
    except Exception as e:
        results.fail("udp_aa_set_for_nxdomain", str(e))

    # --- AA=1 for ANY query response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0xF005)
        resp = sq(pkt)
        if assert_eq(results, "udp_aa_set_for_any", resp.aa, 1, "AA"):
            results.ok("udp_aa_set_for_any")
    except Exception as e:
        results.fail("udp_aa_set_for_any", str(e))

    # --- AA=0 for NOTIMP (server is not authoritative for this error) ---
    try:
        flags = (2 << 11) | 0x0100  # OPCODE=2, RD=1
        header = struct.pack("!HHHHHH", 0xF006, flags, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        resp = sq(header + question)
        ok = True
        ok &= assert_eq(results, "udp_aa_clear_for_notimp", resp.rcode, 4, "RCODE")
        ok &= assert_eq(results, "udp_aa_clear_for_notimp", resp.aa, 0, "AA")
        if ok:
            results.ok("udp_aa_clear_for_notimp")
    except Exception as e:
        results.fail("udp_aa_clear_for_notimp", str(e))

    # --- AA=0 for FORMERR (malformed packet) ---
    try:
        malformed = struct.pack("!HHHHHH", 0xF007, 0x0100, 1, 0, 0, 0)
        resp = sq(malformed)
        ok = True
        ok &= assert_eq(results, "udp_aa_clear_for_formerr", resp.rcode, 1, "RCODE")
        ok &= assert_eq(results, "udp_aa_clear_for_formerr", resp.aa, 0, "AA")
        if ok:
            results.ok("udp_aa_clear_for_formerr")
    except Exception as e:
        results.fail("udp_aa_clear_for_formerr", str(e))

    # ========================================================================
    # RFC COMPLIANCE: RESPONSE STRUCTURE - RFC 1035 §4.1
    # ========================================================================

    # --- Response packet minimum size (header=12 + question) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF010)
        resp = sq(pkt)
        ok = True
        ok &= (len(resp.data) >= 12)  # At minimum a header
        ok &= assert_eq(results, "udp_response_min_size", resp.qdcount, 1, "QDCOUNT")
        if ok:
            results.ok("udp_response_min_size")
        else:
            results.fail("udp_response_min_size", f"packet too small: {len(resp.data)} bytes")
    except Exception as e:
        results.fail("udp_response_min_size", str(e))

    # --- A record RDLENGTH is exactly 4 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF011)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "udp_a_rdlength_4", resp.answers[0].rdlength, 4, "RDLENGTH")
        else:
            ok = False
        if ok:
            results.ok("udp_a_rdlength_4")
    except Exception as e:
        results.fail("udp_a_rdlength_4", str(e))

    # --- AAAA record RDLENGTH is exactly 16 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0xF012)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "udp_aaaa_rdlength_16", resp.answers[0].rdlength, 16, "RDLENGTH")
        else:
            ok = False
        if ok:
            results.ok("udp_aaaa_rdlength_16")
    except Exception as e:
        results.fail("udp_aaaa_rdlength_16", str(e))

    # --- CNAME RDATA is valid wire-format domain name ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_CNAME, txn_id=0xF013)
        resp = sq(pkt)
        ok = True
        if resp.answers:
            domain = resp.answers[0].as_domain()
            # Must end with a dot (FQDN), must have at least two labels
            ok &= domain.endswith(".")
            ok &= domain.count(".") >= 2
            if not ok:
                results.fail("udp_cname_rdata_valid", f"invalid domain: {domain}")
        else:
            ok = False
        if ok:
            results.ok("udp_cname_rdata_valid")
    except Exception as e:
        results.fail("udp_cname_rdata_valid", str(e))

    # --- NXDOMAIN has ANCOUNT=0 and QDCOUNT=1 ---
    try:
        pkt = DnsQuery.build("scea.com", qtype=QTYPE_A, txn_id=0xF014)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_nxdomain_counts", resp.rcode, 3, "RCODE")
        ok &= assert_eq(results, "udp_nxdomain_counts", resp.ancount, 0, "ANCOUNT")
        ok &= assert_eq(results, "udp_nxdomain_counts", resp.qdcount, 1, "QDCOUNT")
        ok &= assert_eq(results, "udp_nxdomain_counts", resp.nscount, 1, "NSCOUNT")
        if ok:
            results.ok("udp_nxdomain_counts")
    except Exception as e:
        results.fail("udp_nxdomain_counts", str(e))

    # --- NOERROR response has correct section counts ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF015)
        resp = sq(pkt)
        ok = True
        ok &= assert_eq(results, "udp_noerror_counts", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "udp_noerror_counts", resp.qdcount, 1, "QDCOUNT")
        ok &= assert_eq(results, "udp_noerror_counts", resp.ancount, 1, "ANCOUNT")
        ok &= assert_eq(results, "udp_noerror_counts", resp.nscount, 0, "NSCOUNT")
        ok &= assert_eq(results, "udp_noerror_counts", resp.arcount, 0, "ARCOUNT")
        if ok:
            results.ok("udp_noerror_counts")
    except Exception as e:
        results.fail("udp_noerror_counts", str(e))

    # --- Z bits are zero (reserved, RFC 1035 §4.1.1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF016)
        resp = sq(pkt)
        # Z is bit 6 of the flags field (between RA and RCODE)
        z_bit = (resp.flags >> 6) & 1
        if assert_eq(results, "udp_z_bits_zero", z_bit, 0, "Z"):
            results.ok("udp_z_bits_zero")
    except Exception as e:
        results.fail("udp_z_bits_zero", str(e))

    # ========================================================================
    # TCP TRANSPORT TESTS (RFC 1035 §4.2.2)
    # ========================================================================

    def stq(data):
        return send_tcp_query(data, DNS_IP, port)

    # --- TCP: A record query ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_record", resp.txn_id, 0xF101, "txn_id")
        ok &= assert_eq(results, "tcp_a_record", resp.qr, 1, "QR")
        ok &= assert_eq(results, "tcp_a_record", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_record", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_record", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_record")
    except Exception as e:
        results.fail("tcp_a_record", str(e))

    # --- TCP: AAAA record query ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0xF102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_aaaa_record", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_aaaa_record", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_aaaa_record", resp.answers[0].rtype, QTYPE_AAAA, "type")
            ok &= assert_eq(results, "tcp_aaaa_record", resp.answers[0].as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "IPv6")
        else:
            ok = False
        if ok:
            results.ok("tcp_aaaa_record")
    except Exception as e:
        results.fail("tcp_aaaa_record", str(e))

    # --- TCP: CNAME record query ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_A, txn_id=0xF103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_cname", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "tcp_cname", cname_answers[0].as_domain(), "b0.ww.np.dl.playstation.net.edgesuite.net.", "CNAME target")
        else:
            ok = False
            results.fail("tcp_cname", "no CNAME answer")
        if ok:
            results.ok("tcp_cname")
    except Exception as e:
        results.fail("tcp_cname", str(e))

    # --- TCP: Blocked domain returns NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_A, txn_id=0xF104)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_blocked_nxdomain", resp.rcode, 3, "RCODE (NXDOMAIN)")
        ok &= assert_eq(results, "tcp_blocked_nxdomain", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("tcp_blocked_nxdomain")
    except Exception as e:
        results.fail("tcp_blocked_nxdomain", str(e))

    # --- TCP: Transaction ID preserved ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xCAFE)
        resp = stq(pkt)
        if assert_eq(results, "tcp_txn_id_preserved", resp.txn_id, 0xCAFE, "txn_id"):
            results.ok("tcp_txn_id_preserved")
    except Exception as e:
        results.fail("tcp_txn_id_preserved", str(e))

    # --- TCP: ANY query returns A + AAAA ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0xF106)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_query", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("tcp_any_query", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            a_records = resp.get_answers_by_type(QTYPE_A)
            aaaa_records = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_records) >= 1)
            ok &= (len(aaaa_records) >= 1)
            if ok:
                results.ok("tcp_any_query")
    except Exception as e:
        results.fail("tcp_any_query", str(e))

    # --- TCP: FORMERR for malformed packet ---
    try:
        malformed = struct.pack("!HHHHHH", 0xF107, 0x0100, 1, 0, 0, 0)
        resp = stq(malformed)
        ok = True
        ok &= assert_eq(results, "tcp_formerr", resp.txn_id, 0xF107, "txn_id")
        ok &= assert_eq(results, "tcp_formerr", resp.qr, 1, "QR")
        ok &= assert_eq(results, "tcp_formerr", resp.rcode, 1, "RCODE (FORMERR)")
        if ok:
            results.ok("tcp_formerr")
    except Exception as e:
        results.fail("tcp_formerr", str(e))

    # --- TCP: NOTIMP for non-standard opcode ---
    try:
        flags = (2 << 11) | 0x0100  # OPCODE=2, RD=1
        header = struct.pack("!HHHHHH", 0xF108, flags, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00"
        question += struct.pack("!HH", 1, 1)
        pkt = header + question
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_notimp", resp.txn_id, 0xF108, "txn_id")
        ok &= assert_eq(results, "tcp_notimp", resp.rcode, 4, "RCODE (NOTIMP)")
        if ok:
            results.ok("tcp_notimp")
    except Exception as e:
        results.fail("tcp_notimp", str(e))

    # --- TCP: Header flags (QR=1, RA=1, AA=1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF109)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_header_flags", resp.qr, 1, "QR")
        ok &= assert_eq(results, "tcp_header_flags", resp.ra, 1, "RA")
        ok &= assert_eq(results, "tcp_header_flags", resp.aa, 1, "AA")
        ok &= assert_eq(results, "tcp_header_flags", resp.rcode, 0, "RCODE")
        if ok:
            results.ok("tcp_header_flags")
    except Exception as e:
        results.fail("tcp_header_flags", str(e))

    # --- TCP: Multiple queries on same connection ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((DNS_IP, port))
        all_ok = True
        domains = [
            ("playstation.com", QTYPE_A, 0),
            ("nintendo.net", QTYPE_AAAA, 0),
            ("nintendo.com", QTYPE_A, 3),  # blocked -> NXDOMAIN
        ]
        for i, (domain, qtype, expected_rcode) in enumerate(domains):
            tid = 0xDA00 + i
            query = DnsQuery.build(domain, qtype=qtype, txn_id=tid)
            length_prefix = struct.pack("!H", len(query))
            sock.sendall(length_prefix + query)
            # Read 2-byte length prefix of response
            resp_len_data = b""
            while len(resp_len_data) < 2:
                chunk = sock.recv(2 - len(resp_len_data))
                if not chunk:
                    raise ConnectionError("Connection closed")
                resp_len_data += chunk
            resp_len = struct.unpack("!H", resp_len_data)[0]
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = sock.recv(resp_len - len(resp_data))
                if not chunk:
                    raise ConnectionError("Connection closed")
                resp_data += chunk
            resp = DnsResponse(resp_data)
            if resp.txn_id != tid:
                all_ok = False
                results.fail("tcp_multi_query_conn", f"{domain}: txn_id mismatch 0x{resp.txn_id:04x} != 0x{tid:04x}")
                break
            if resp.rcode != expected_rcode:
                all_ok = False
                results.fail("tcp_multi_query_conn", f"{domain}: rcode={resp.rcode}, expected {expected_rcode}")
                break
        sock.close()
        if all_ok:
            results.ok("tcp_multi_query_conn")
    except Exception as e:
        results.fail("tcp_multi_query_conn", str(e))

    # --- TCP: Wildcard subdomain ---
    try:
        pkt = DnsQuery.build("random.playstation.com", qtype=QTYPE_A, txn_id=0xF110)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_wildcard", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_wildcard")
    except Exception as e:
        results.fail("tcp_wildcard", str(e))

    # --- TCP: Rapid sequential queries ---
    try:
        all_ok = True
        for i in range(5):
            tid = 0xDB00 + i
            pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=tid)
            resp = stq(pkt)
            if resp.txn_id != tid or resp.rcode != 0:
                all_ok = False
                results.fail("tcp_rapid_queries", f"Failed on iteration {i}: txn_id=0x{resp.txn_id:04x}, rcode={resp.rcode}")
                break
        if all_ok:
            results.ok("tcp_rapid_queries")
    except Exception as e:
        results.fail("tcp_rapid_queries", str(e))

    # ========================================================================
    # TCP: A RECORD TESTS
    # ========================================================================

    # --- TCP: A record: root domain ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x1101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_root_domain", resp.txn_id, 0x1101, "txn_id")
        ok &= assert_eq(results, "tcp_a_root_domain", resp.qr, 1, "QR")
        ok &= assert_eq(results, "tcp_a_root_domain", resp.rd, 1, "RD")
        ok &= assert_eq(results, "tcp_a_root_domain", resp.ra, 1, "RA")
        ok &= assert_eq(results, "tcp_a_root_domain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_root_domain", resp.qdcount, 1, "QDCOUNT")
        ok &= assert_eq(results, "tcp_a_root_domain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            a = resp.answers[0]
            ok &= assert_eq(results, "tcp_a_root_domain", a.rtype, QTYPE_A, "answer type")
            ok &= assert_eq(results, "tcp_a_root_domain", a.as_ipv4(), "0.0.0.0", "IP")
            ok &= assert_eq(results, "tcp_a_root_domain", a.ttl, 3600, "TTL")
            ok &= assert_eq(results, "tcp_a_root_domain", a.rclass, 1, "CLASS")
        else:
            ok = False
            results.fail("tcp_a_root_domain", "no answer records")
        if ok:
            results.ok("tcp_a_root_domain")
    except Exception as e:
        results.fail("tcp_a_root_domain", str(e))

    # --- TCP: A record: wildcard subdomain ---
    try:
        pkt = DnsQuery.build("random.playstation.com", qtype=QTYPE_A, txn_id=0x1102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_wildcard", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_wildcard")
    except Exception as e:
        results.fail("tcp_a_wildcard", str(e))

    # --- TCP: A record: specific subdomain (www.playstation.com) ---
    try:
        pkt = DnsQuery.build("www.playstation.com", qtype=QTYPE_A, txn_id=0x1103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_www_subdomain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_www_subdomain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_www_subdomain", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_www_subdomain")
    except Exception as e:
        results.fail("tcp_a_www_subdomain", str(e))

    # --- TCP: A record: deep wildcard subdomain ---
    try:
        pkt = DnsQuery.build("a.b.c.playstation.com", qtype=QTYPE_A, txn_id=0x1105)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_deep_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_deep_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_deep_wildcard", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_deep_wildcard")
    except Exception as e:
        results.fail("tcp_a_deep_wildcard", str(e))

    # --- TCP: A record: regex subdomain (ctest.cdn.nintendo.net) ---
    try:
        pkt = DnsQuery.build("ctest.cdn.nintendo.net", qtype=QTYPE_A, txn_id=0x1106)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_regex_subdomain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_regex_subdomain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_regex_subdomain", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_regex_subdomain")
    except Exception as e:
        results.fail("tcp_a_regex_subdomain", str(e))

    # --- TCP: A record: complex regex (djp01.ps4.update.playstation.net) ---
    try:
        pkt = DnsQuery.build("djp01.ps4.update.playstation.net", qtype=QTYPE_A, txn_id=0x1107)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_a_complex_regex", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_a_complex_regex", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_complex_regex", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_complex_regex")
    except Exception as e:
        results.fail("tcp_a_complex_regex", str(e))

    # ========================================================================
    # TCP: AAAA RECORD TESTS
    # ========================================================================

    # --- TCP: AAAA record: root domain ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0x2101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_aaaa_root_domain", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_aaaa_root_domain", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            a = resp.answers[0]
            ok &= assert_eq(results, "tcp_aaaa_root_domain", a.rtype, QTYPE_AAAA, "answer type")
            ok &= assert_eq(results, "tcp_aaaa_root_domain", a.as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "IPv6")
            ok &= assert_eq(results, "tcp_aaaa_root_domain", a.rdlength, 16, "RDLENGTH")
        else:
            ok = False
        if ok:
            results.ok("tcp_aaaa_root_domain")
    except Exception as e:
        results.fail("tcp_aaaa_root_domain", str(e))

    # --- TCP: AAAA record: wildcard subdomain ---
    try:
        pkt = DnsQuery.build("sub.playstation.com", qtype=QTYPE_AAAA, txn_id=0x2102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_aaaa_wildcard", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_aaaa_wildcard", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_aaaa_wildcard", resp.answers[0].as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "IPv6")
        else:
            ok = False
        if ok:
            results.ok("tcp_aaaa_wildcard")
    except Exception as e:
        results.fail("tcp_aaaa_wildcard", str(e))

    # ========================================================================
    # TCP: CNAME RECORD TESTS
    # ========================================================================

    # --- TCP: CNAME: gs.ww.np.dl subdomain ---
    try:
        pkt = DnsQuery.build("gs.ww.np.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_cname_gs_subdomain", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "tcp_cname_gs_subdomain", cname_answers[0].as_domain(), "gs.ww.np.dl.playstation.net.edgesuite.net.", "CNAME target")
        else:
            ok = False
            results.fail("tcp_cname_gs_subdomain", "no CNAME")
        if ok:
            results.ok("tcp_cname_gs_subdomain")
    except Exception as e:
        results.fail("tcp_cname_gs_subdomain", str(e))

    # --- TCP: CNAME: gs2.ww.prod.dl subdomain ---
    try:
        pkt = DnsQuery.build("gs2.ww.prod.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_cname_gs2_subdomain", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "tcp_cname_gs2_subdomain", cname_answers[0].as_domain(), "gs2.ww.prod.dl.playstation.net.edgesuite.net.", "target")
        else:
            ok = False
            results.fail("tcp_cname_gs2_subdomain", "no CNAME")
        if ok:
            results.ok("tcp_cname_gs2_subdomain")
    except Exception as e:
        results.fail("tcp_cname_gs2_subdomain", str(e))

    # --- TCP: CNAME: gst.prod.dl subdomain ---
    try:
        pkt = DnsQuery.build("gst.prod.dl.playstation.net", qtype=QTYPE_A, txn_id=0x3104)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_cname_gst_subdomain", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "tcp_cname_gst_subdomain", cname_answers[0].as_domain(), "gst.prod.dl.playstation.net.edgesuite.net.", "target")
        else:
            ok = False
            results.fail("tcp_cname_gst_subdomain", "no CNAME")
        if ok:
            results.ok("tcp_cname_gst_subdomain")
    except Exception as e:
        results.fail("tcp_cname_gst_subdomain", str(e))

    # --- TCP: CNAME: direct CNAME type query ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_CNAME, txn_id=0x3105)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_cname_direct_query", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_cname_direct_query", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_cname_direct_query", resp.answers[0].rtype, QTYPE_CNAME, "answer type")
            ok &= assert_eq(results, "tcp_cname_direct_query", resp.answers[0].as_domain(), "b0.ww.np.dl.playstation.net.edgesuite.net.", "target")
        else:
            ok = False
        if ok:
            results.ok("tcp_cname_direct_query")
    except Exception as e:
        results.fail("tcp_cname_direct_query", str(e))

    # --- TCP: CNAME falls through to A for non-CNAME subdomain ---
    try:
        pkt = DnsQuery.build("manuals.playstation.net", qtype=QTYPE_A, txn_id=0x3106)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_no_cname_fallthrough", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_no_cname_fallthrough", resp.ancount, 1, "ANCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_no_cname_fallthrough", resp.answers[0].rtype, QTYPE_A, "answer type")
            ok &= assert_eq(results, "tcp_no_cname_fallthrough", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_no_cname_fallthrough")
    except Exception as e:
        results.fail("tcp_no_cname_fallthrough", str(e))

    # ========================================================================
    # TCP: BLOCKED DOMAIN TESTS
    # ========================================================================

    # --- TCP: Blocked domain: AAAA query -> NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_AAAA, txn_id=0x4102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_blocked_aaaa_nxdomain", resp.rcode, 3, "RCODE")
        ok &= assert_eq(results, "tcp_blocked_aaaa_nxdomain", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("tcp_blocked_aaaa_nxdomain")
    except Exception as e:
        results.fail("tcp_blocked_aaaa_nxdomain", str(e))

    # --- TCP: Blocked domain: subdomain also blocked ---
    try:
        pkt = DnsQuery.build("www.nintendo.com", qtype=QTYPE_A, txn_id=0x4103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_blocked_subdomain", resp.rcode, 3, "RCODE (NXDOMAIN)")
        ok &= assert_eq(results, "tcp_blocked_subdomain", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("tcp_blocked_subdomain")
    except Exception as e:
        results.fail("tcp_blocked_subdomain", str(e))

    # --- TCP: Multiple different blocked domains ---
    try:
        blocked_domains = [
            "scea.com", "playstation.org", "sie-rd.com",
            "sonyentertainmentnetwork.com", "nintendoswitch.com",
        ]
        all_ok = True
        for domain in blocked_domains:
            pkt = DnsQuery.build(domain, qtype=QTYPE_A, txn_id=0x4110)
            resp = stq(pkt)
            if resp.rcode != 3:
                all_ok = False
                results.fail("tcp_blocked_multiple", f"{domain}: RCODE={resp.rcode}, expected 3")
                break
        if all_ok:
            results.ok("tcp_blocked_multiple")
    except Exception as e:
        results.fail("tcp_blocked_multiple", str(e))

    # ========================================================================
    # TCP: ANY QUERY TESTS
    # ========================================================================

    # --- TCP: ANY query: root domain returns A + AAAA ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0x5101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_root_multi", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("tcp_any_root_multi", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            a_records = resp.get_answers_by_type(QTYPE_A)
            aaaa_records = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_records) >= 1)
            ok &= (len(aaaa_records) >= 1)
            if a_records:
                ok &= assert_eq(results, "tcp_any_root_multi", a_records[0].as_ipv4(), "0.0.0.0", "A IP")
            if aaaa_records:
                ok &= assert_eq(results, "tcp_any_root_multi", aaaa_records[0].as_ipv6(), "0000:0000:0000:0000:0000:0000:0000:0000", "AAAA IP")
            if ok:
                results.ok("tcp_any_root_multi")
    except Exception as e:
        results.fail("tcp_any_root_multi", str(e))

    # --- TCP: ANY query: wildcard subdomain ---
    try:
        pkt = DnsQuery.build("anything.playstation.com", qtype=QTYPE_ANY, txn_id=0x5102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_wildcard_multi", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("tcp_any_wildcard_multi", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            a_records = resp.get_answers_by_type(QTYPE_A)
            aaaa_records = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_records) >= 1)
            ok &= (len(aaaa_records) >= 1)
            if ok:
                results.ok("tcp_any_wildcard_multi")
    except Exception as e:
        results.fail("tcp_any_wildcard_multi", str(e))

    # --- TCP: ANY query: zone with CNAME entries ---
    try:
        pkt = DnsQuery.build("playstation.net", qtype=QTYPE_ANY, txn_id=0x5103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_with_cname_zone", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("tcp_any_with_cname_zone", f"ANCOUNT={resp.ancount}, expected >= 2")
        else:
            a_recs = resp.get_answers_by_type(QTYPE_A)
            aaaa_recs = resp.get_answers_by_type(QTYPE_AAAA)
            ok &= (len(a_recs) >= 1)
            ok &= (len(aaaa_recs) >= 1)
            if ok:
                results.ok("tcp_any_with_cname_zone")
    except Exception as e:
        results.fail("tcp_any_with_cname_zone", str(e))

    # --- TCP: ANY query: blocked domain returns NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_ANY, txn_id=0x5104)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_blocked", resp.rcode, 3, "RCODE (NXDOMAIN)")
        ok &= assert_eq(results, "tcp_any_blocked", resp.ancount, 0, "ANCOUNT")
        if ok:
            results.ok("tcp_any_blocked")
    except Exception as e:
        results.fail("tcp_any_blocked", str(e))

    # ========================================================================
    # TCP: HEADER FLAGS / PROTOCOL TESTS
    # ========================================================================

    # --- TCP: RD bit echoed (RD=1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6101, rd=True)
        resp = stq(pkt)
        if assert_eq(results, "tcp_rd_echoed_1", resp.rd, 1, "RD"):
            results.ok("tcp_rd_echoed_1")
    except Exception as e:
        results.fail("tcp_rd_echoed_1", str(e))

    # --- TCP: RD bit echoed (RD=0) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6102, rd=False)
        resp = stq(pkt)
        if assert_eq(results, "tcp_rd_echoed_0", resp.rd, 0, "RD"):
            results.ok("tcp_rd_echoed_0")
    except Exception as e:
        results.fail("tcp_rd_echoed_0", str(e))

    # --- TCP: QR bit is 1 (response) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6103)
        resp = stq(pkt)
        if assert_eq(results, "tcp_qr_is_response", resp.qr, 1, "QR"):
            results.ok("tcp_qr_is_response")
    except Exception as e:
        results.fail("tcp_qr_is_response", str(e))

    # --- TCP: RA bit is 1 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6104)
        resp = stq(pkt)
        if assert_eq(results, "tcp_ra_set", resp.ra, 1, "RA"):
            results.ok("tcp_ra_set")
    except Exception as e:
        results.fail("tcp_ra_set", str(e))

    # --- TCP: TC bit is 0 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6105)
        resp = stq(pkt)
        if assert_eq(results, "tcp_tc_not_set", resp.tc, 0, "TC"):
            results.ok("tcp_tc_not_set")
    except Exception as e:
        results.fail("tcp_tc_not_set", str(e))

    # --- TCP: OPCODE echoed as 0 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6106)
        resp = stq(pkt)
        if assert_eq(results, "tcp_opcode_standard", resp.opcode, 0, "OPCODE"):
            results.ok("tcp_opcode_standard")
    except Exception as e:
        results.fail("tcp_opcode_standard", str(e))

    # --- TCP: QDCOUNT is 1 in response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x6107)
        resp = stq(pkt)
        if assert_eq(results, "tcp_qdcount_one", resp.qdcount, 1, "QDCOUNT"):
            results.ok("tcp_qdcount_one")
    except Exception as e:
        results.fail("tcp_qdcount_one", str(e))

    # ========================================================================
    # TCP: EDNS0 TESTS
    # ========================================================================

    # --- TCP: EDNS0 query accepted ---
    try:
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_edns0_accepted", resp.txn_id, 0x7101, "txn_id")
        ok &= assert_eq(results, "tcp_edns0_accepted", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_edns0_accepted", resp.ancount, 1, "ANCOUNT")
        ok &= assert_eq(results, "tcp_edns0_accepted", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "tcp_edns0_accepted", resp.opt.version, 0, "EDNS version")
            ok &= assert_eq(results, "tcp_edns0_accepted", resp.opt.udp_payload_size, 1232, "UDP payload size")
        else:
            ok = False
            results.fail("tcp_edns0_accepted", "no OPT record parsed")
        if ok:
            results.ok("tcp_edns0_accepted")
    except Exception as e:
        results.fail("tcp_edns0_accepted", str(e))

    # --- TCP: EDNS0 query with unknown option ignored ---
    try:
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7105, options=[(65001, b"ignore")])
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_edns0_unknown_option", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_edns0_unknown_option", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "tcp_edns0_unknown_option", len(resp.opt.options), 0, "unknown option ignored")
        else:
            ok = False
            results.fail("tcp_edns0_unknown_option", "no OPT record parsed")
        if ok:
            results.ok("tcp_edns0_unknown_option")
    except Exception as e:
        results.fail("tcp_edns0_unknown_option", str(e))

    # --- TCP: EDNS0 query with COOKIE option echoed ---
    try:
        cookie = b"\x09\x08\x07\x06\x05\x04\x03\x02"
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7103, options=[(10, cookie)])
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_edns0_cookie_echo", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_edns0_cookie_echo", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "tcp_edns0_cookie_echo", resp.opt.version, 0, "EDNS version")
            ok &= assert_eq(results, "tcp_edns0_cookie_echo", resp.opt.options[0][0], 10, "OPTION code")
            ok &= assert_eq(results, "tcp_edns0_cookie_echo", resp.opt.options[0][1], cookie, "OPTION data")
        else:
            ok = False
            results.fail("tcp_edns0_cookie_echo", "no OPT record parsed")
        if ok:
            results.ok("tcp_edns0_cookie_echo")
    except Exception as e:
        results.fail("tcp_edns0_cookie_echo", str(e))

    # --- TCP: EDNS0 query with BADVERS version ---
    try:
        pkt = DnsQuery.build_edns0("playstation.com", qtype=QTYPE_A, txn_id=0x7104, version=1)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_edns0_badvers", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_edns0_badvers", resp.arcount, 1, "ARCOUNT")
        if resp.opt is not None:
            ok &= assert_eq(results, "tcp_edns0_badvers", resp.opt.extended_rcode, 1, "Extended RCODE")
            ok &= assert_eq(results, "tcp_edns0_badvers", resp.opt.version, 0, "Response EDNS version")
        else:
            ok = False
            results.fail("tcp_edns0_badvers", "no OPT record parsed")
        if ok:
            results.ok("tcp_edns0_badvers")
    except Exception as e:
        results.fail("tcp_edns0_badvers", str(e))

    # --- TCP: EDNS0 query with AAAA ---
    try:
        pkt = DnsQuery.build_edns0("nintendo.net", qtype=QTYPE_AAAA, txn_id=0x7102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_edns0_aaaa", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_edns0_aaaa", resp.ancount, 1, "ANCOUNT")
        ok &= assert_eq(results, "tcp_edns0_aaaa", resp.arcount, 1, "ARCOUNT")
        if resp.answers:
            ok &= assert_eq(results, "tcp_edns0_aaaa", resp.answers[0].rtype, QTYPE_AAAA, "type")
        else:
            ok = False
        if ok:
            results.ok("tcp_edns0_aaaa")
    except Exception as e:
        results.fail("tcp_edns0_aaaa", str(e))

    # ========================================================================
    # TCP: ERROR RESPONSE TESTS
    # ========================================================================

    # --- TCP: Server survives FORMERR and responds to next query ---
    try:
        malformed = struct.pack("!HHHHHH", 0x8103, 0x0100, 1, 0, 0, 0)
        try:
            stq(malformed)
        except Exception:
            pass
        time.sleep(0.1)
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x8104)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_survives_formerr", resp.txn_id, 0x8104, "txn_id")
        ok &= assert_eq(results, "tcp_survives_formerr", resp.rcode, 0, "RCODE")
        if ok:
            results.ok("tcp_survives_formerr")
    except Exception as e:
        results.fail("tcp_survives_formerr", str(e))

    # ========================================================================
    # TCP: ANSWER SECTION DATA VALIDATION
    # ========================================================================

    # --- TCP: A record answer name resolves correctly ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x9101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_answer_uses_pointer", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_answer_uses_pointer", resp.answers[0].name, "playstation.com.", "answer name")
        else:
            ok = False
        if ok:
            results.ok("tcp_answer_uses_pointer")
    except Exception as e:
        results.fail("tcp_answer_uses_pointer", str(e))

    # --- TCP: A record TTL ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_A, txn_id=0x9102)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "tcp_ttl_default", resp.answers[0].ttl, 3600, "TTL")
        else:
            ok = False
        if ok:
            results.ok("tcp_ttl_default")
    except Exception as e:
        results.fail("tcp_ttl_default", str(e))

    # --- TCP: AAAA record: all 16 bytes are zeros ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_AAAA, txn_id=0x9103)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            rdata = resp.answers[0].rdata_bytes()
            ok &= assert_eq(results, "tcp_aaaa_all_zeros", len(rdata), 16, "RDLENGTH")
            ok &= assert_eq(results, "tcp_aaaa_all_zeros", rdata, b"\x00" * 16, "IPv6 bytes")
        else:
            ok = False
        if ok:
            results.ok("tcp_aaaa_all_zeros")
    except Exception as e:
        results.fail("tcp_aaaa_all_zeros", str(e))

    # --- TCP: A record RDATA is exactly 4 bytes of zeros ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0x9104)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            rdata = resp.answers[0].rdata_bytes()
            ok &= assert_eq(results, "tcp_a_rdata_zero", len(rdata), 4, "RDLENGTH")
            ok &= assert_eq(results, "tcp_a_rdata_zero", rdata, b"\x00\x00\x00\x00", "IPv4 bytes")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_rdata_zero")
    except Exception as e:
        results.fail("tcp_a_rdata_zero", str(e))

    # --- TCP: Answer CLASS is IN (1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, qclass=1, txn_id=0x9105)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "tcp_answer_class_in", resp.answers[0].rclass, 1, "CLASS")
        else:
            ok = False
        if ok:
            results.ok("tcp_answer_class_in")
    except Exception as e:
        results.fail("tcp_answer_class_in", str(e))

    # ========================================================================
    # TCP: MULTI-ZONE TESTS
    # ========================================================================

    # --- TCP: nintendo.net A root ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_A, txn_id=0xA101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_zone_nintendo_net", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_zone_nintendo_net", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_zone_nintendo_net")
    except Exception as e:
        results.fail("tcp_zone_nintendo_net", str(e))

    # --- TCP: wii.com A root ---
    try:
        pkt = DnsQuery.build("wii.com", qtype=QTYPE_A, txn_id=0xA102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_zone_wii_com", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_zone_wii_com", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_zone_wii_com")
    except Exception as e:
        results.fail("tcp_zone_wii_com", str(e))

    # --- TCP: nintendowifi.net A root ---
    try:
        pkt = DnsQuery.build("nintendowifi.net", qtype=QTYPE_A, txn_id=0xA103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_zone_nintendowifi", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_zone_nintendowifi", resp.answers[0].as_ipv4(), "0.0.0.0", "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_zone_nintendowifi")
    except Exception as e:
        results.fail("tcp_zone_nintendowifi", str(e))

    # --- TCP: conntest.nintendowifi.net ---
    try:
        pkt = DnsQuery.build("conntest.nintendowifi.net", qtype=QTYPE_A, txn_id=0xA104)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_zone_conntest", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_zone_conntest", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_zone_conntest")
    except Exception as e:
        results.fail("tcp_zone_conntest", str(e))

    # --- TCP: cfh.wapp.wii.com ---
    try:
        pkt = DnsQuery.build("cfh.wapp.wii.com", qtype=QTYPE_A, txn_id=0xA105)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_zone_cfh_wapp", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_zone_cfh_wapp", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_zone_cfh_wapp")
    except Exception as e:
        results.fail("tcp_zone_cfh_wapp", str(e))

    # ========================================================================
    # TCP: RAPID / STRESS TESTS
    # ========================================================================

    # --- TCP: Rapid queries across different domains ---
    try:
        domains = [
            ("playstation.com", QTYPE_A, 0),
            ("nintendo.net", QTYPE_AAAA, 0),
            ("wii.com", QTYPE_A, 0),
            ("nintendo.com", QTYPE_A, 3),  # blocked -> NXDOMAIN
            ("playstation.net", QTYPE_A, 0),
        ]
        all_ok = True
        for i, (domain, qtype, expected_rcode) in enumerate(domains):
            tid = 0xB200 + i
            pkt = DnsQuery.build(domain, qtype=qtype, txn_id=tid)
            resp = stq(pkt)
            if resp.txn_id != tid:
                all_ok = False
                results.fail("tcp_rapid_cross_domain", f"{domain}: txn_id mismatch")
                break
            if resp.rcode != expected_rcode:
                all_ok = False
                results.fail("tcp_rapid_cross_domain", f"{domain}: rcode={resp.rcode}, expected {expected_rcode}")
                break
        if all_ok:
            results.ok("tcp_rapid_cross_domain")
    except Exception as e:
        results.fail("tcp_rapid_cross_domain", str(e))

    # ========================================================================
    # TCP: REGEX PATTERN TESTS
    # ========================================================================

    # --- TCP: fus01.ps5.update.playstation.net ---
    try:
        pkt = DnsQuery.build("fus01.ps5.update.playstation.net", qtype=QTYPE_A, txn_id=0xC101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_regex_fus01_ps5", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_regex_fus01_ps5", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_regex_fus01_ps5")
    except Exception as e:
        results.fail("tcp_regex_fus01_ps5", str(e))

    # --- TCP: heu01.ps4.update.playstation.net ---
    try:
        pkt = DnsQuery.build("heu01.ps4.update.playstation.net", qtype=QTYPE_A, txn_id=0xC102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_regex_heu01_ps4", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_regex_heu01_ps4", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_regex_heu01_ps4")
    except Exception as e:
        results.fail("tcp_regex_heu01_ps4", str(e))

    # --- TCP: get.net.playstation.net ---
    try:
        pkt = DnsQuery.build("get.net.playstation.net", qtype=QTYPE_A, txn_id=0xC103)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_regex_get_net", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_regex_get_net", resp.answers[0].as_ipv4(), REDIRECT_IPV4, "IP")
        else:
            ok = False
        if ok:
            results.ok("tcp_regex_get_net")
    except Exception as e:
        results.fail("tcp_regex_get_net", str(e))

    # --- TCP: AAAA versions of regex subdomains ---
    try:
        pkt = DnsQuery.build("djp01.ps4.update.playstation.net", qtype=QTYPE_AAAA, txn_id=0xC104)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_regex_aaaa", resp.rcode, 0, "RCODE")
        if resp.answers:
            ok &= assert_eq(results, "tcp_regex_aaaa", resp.answers[0].rtype, QTYPE_AAAA, "type")
            ok &= assert_eq(results, "tcp_regex_aaaa", resp.answers[0].as_ipv6(), REDIRECT_IPV6, "IPv6")
        else:
            ok = False
        if ok:
            results.ok("tcp_regex_aaaa")
    except Exception as e:
        results.fail("tcp_regex_aaaa", str(e))

    # ========================================================================
    # TCP: CNAME WITH AAAA QUERY
    # ========================================================================

    # --- TCP: CNAME returned for AAAA query ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_AAAA, txn_id=0xD101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_cname_with_aaaa", resp.rcode, 0, "RCODE")
        cname_answers = resp.get_answers_by_type(QTYPE_CNAME)
        if cname_answers:
            ok &= assert_eq(results, "tcp_cname_with_aaaa", cname_answers[0].as_domain(), "b0.ww.np.dl.playstation.net.edgesuite.net.", "CNAME target")
        else:
            ok = False
            results.fail("tcp_cname_with_aaaa", "no CNAME answer for AAAA query")
        if ok:
            results.ok("tcp_cname_with_aaaa")
    except Exception as e:
        results.fail("tcp_cname_with_aaaa", str(e))

    # ========================================================================
    # TCP: MULTI-ANSWER CONTENT VALIDATION
    # ========================================================================

    # --- TCP: ANY returns correct data in both A and AAAA records ---
    try:
        pkt = DnsQuery.build("nintendo.net", qtype=QTYPE_ANY, txn_id=0xE101)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_data_validation", resp.rcode, 0, "RCODE")
        ok &= (resp.ancount >= 2)
        if resp.ancount < 2:
            results.fail("tcp_any_data_validation", f"ANCOUNT={resp.ancount}")
        else:
            a_recs = resp.get_answers_by_type(QTYPE_A)
            aaaa_recs = resp.get_answers_by_type(QTYPE_AAAA)
            if a_recs:
                ok &= assert_eq(results, "tcp_any_data_validation", a_recs[0].as_ipv4(), "0.0.0.0", "A data")
                ok &= assert_eq(results, "tcp_any_data_validation", a_recs[0].ttl, 3600, "A TTL")
            else:
                ok = False
            if aaaa_recs:
                ok &= assert_eq(results, "tcp_any_data_validation", aaaa_recs[0].rdata_bytes(), b"\x00" * 16, "AAAA bytes")
                ok &= assert_eq(results, "tcp_any_data_validation", aaaa_recs[0].ttl, 3600, "AAAA TTL")
            else:
                ok = False
            if ok:
                results.ok("tcp_any_data_validation")
    except Exception as e:
        results.fail("tcp_any_data_validation", str(e))

    # --- TCP: All answer records in ANY have CLASS=IN ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0xE102)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_any_class_check", resp.rcode, 0, "RCODE")
        for i, ans in enumerate(resp.answers):
            if ans.rclass != 1:
                ok = False
                results.fail("tcp_any_class_check", f"answer[{i}] CLASS={ans.rclass}, expected 1")
                break
        if ok and resp.answers:
            results.ok("tcp_any_class_check")
        elif not resp.answers:
            results.fail("tcp_any_class_check", "no answers")
    except Exception as e:
        results.fail("tcp_any_class_check", str(e))

    # ========================================================================
    # TCP: RFC COMPLIANCE: AA BIT
    # ========================================================================

    # --- TCP: AA=1 for authoritative A record response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF201)
        resp = stq(pkt)
        if assert_eq(results, "tcp_aa_set_for_a", resp.aa, 1, "AA"):
            results.ok("tcp_aa_set_for_a")
    except Exception as e:
        results.fail("tcp_aa_set_for_a", str(e))

    # --- TCP: AA=1 for authoritative AAAA record response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0xF202)
        resp = stq(pkt)
        if assert_eq(results, "tcp_aa_set_for_aaaa", resp.aa, 1, "AA"):
            results.ok("tcp_aa_set_for_aaaa")
    except Exception as e:
        results.fail("tcp_aa_set_for_aaaa", str(e))

    # --- TCP: AA=1 for authoritative CNAME response ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_CNAME, txn_id=0xF203)
        resp = stq(pkt)
        if assert_eq(results, "tcp_aa_set_for_cname", resp.aa, 1, "AA"):
            results.ok("tcp_aa_set_for_cname")
    except Exception as e:
        results.fail("tcp_aa_set_for_cname", str(e))

    # --- TCP: AA=1 for blocked domain NXDOMAIN ---
    try:
        pkt = DnsQuery.build("nintendo.com", qtype=QTYPE_A, txn_id=0xF204)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_aa_set_for_nxdomain", resp.rcode, 3, "RCODE")
        ok &= assert_eq(results, "tcp_aa_set_for_nxdomain", resp.aa, 1, "AA")
        if ok:
            results.ok("tcp_aa_set_for_nxdomain")
    except Exception as e:
        results.fail("tcp_aa_set_for_nxdomain", str(e))

    # --- TCP: AA=1 for ANY query response ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_ANY, txn_id=0xF205)
        resp = stq(pkt)
        if assert_eq(results, "tcp_aa_set_for_any", resp.aa, 1, "AA"):
            results.ok("tcp_aa_set_for_any")
    except Exception as e:
        results.fail("tcp_aa_set_for_any", str(e))

    # --- TCP: AA=0 for NOTIMP ---
    try:
        flags = (2 << 11) | 0x0100  # OPCODE=2, RD=1
        header = struct.pack("!HHHHHH", 0xF206, flags, 1, 0, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        resp = stq(header + question)
        ok = True
        ok &= assert_eq(results, "tcp_aa_clear_for_notimp", resp.rcode, 4, "RCODE")
        ok &= assert_eq(results, "tcp_aa_clear_for_notimp", resp.aa, 0, "AA")
        if ok:
            results.ok("tcp_aa_clear_for_notimp")
    except Exception as e:
        results.fail("tcp_aa_clear_for_notimp", str(e))

    # --- TCP: AA=0 for FORMERR ---
    try:
        malformed = struct.pack("!HHHHHH", 0xF207, 0x0100, 1, 0, 0, 0)
        resp = stq(malformed)
        ok = True
        ok &= assert_eq(results, "tcp_aa_clear_for_formerr", resp.rcode, 1, "RCODE")
        ok &= assert_eq(results, "tcp_aa_clear_for_formerr", resp.aa, 0, "AA")
        if ok:
            results.ok("tcp_aa_clear_for_formerr")
    except Exception as e:
        results.fail("tcp_aa_clear_for_formerr", str(e))

    # ========================================================================
    # TCP: RFC COMPLIANCE: RESPONSE STRUCTURE
    # ========================================================================

    # --- TCP: Response packet minimum size ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF210)
        resp = stq(pkt)
        ok = True
        ok &= (len(resp.data) >= 12)
        ok &= assert_eq(results, "tcp_response_min_size", resp.qdcount, 1, "QDCOUNT")
        if ok:
            results.ok("tcp_response_min_size")
        else:
            results.fail("tcp_response_min_size", f"packet too small: {len(resp.data)} bytes")
    except Exception as e:
        results.fail("tcp_response_min_size", str(e))

    # --- TCP: A record RDLENGTH is exactly 4 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF211)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "tcp_a_rdlength_4", resp.answers[0].rdlength, 4, "RDLENGTH")
        else:
            ok = False
        if ok:
            results.ok("tcp_a_rdlength_4")
    except Exception as e:
        results.fail("tcp_a_rdlength_4", str(e))

    # --- TCP: AAAA record RDLENGTH is exactly 16 ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_AAAA, txn_id=0xF212)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            ok &= assert_eq(results, "tcp_aaaa_rdlength_16", resp.answers[0].rdlength, 16, "RDLENGTH")
        else:
            ok = False
        if ok:
            results.ok("tcp_aaaa_rdlength_16")
    except Exception as e:
        results.fail("tcp_aaaa_rdlength_16", str(e))

    # --- TCP: CNAME RDATA is valid wire-format domain name ---
    try:
        pkt = DnsQuery.build("b0.ww.np.dl.playstation.net", qtype=QTYPE_CNAME, txn_id=0xF213)
        resp = stq(pkt)
        ok = True
        if resp.answers:
            domain = resp.answers[0].as_domain()
            ok &= domain.endswith(".")
            ok &= domain.count(".") >= 2
            if not ok:
                results.fail("tcp_cname_rdata_valid", f"invalid domain: {domain}")
        else:
            ok = False
        if ok:
            results.ok("tcp_cname_rdata_valid")
    except Exception as e:
        results.fail("tcp_cname_rdata_valid", str(e))

    # --- TCP: NXDOMAIN has ANCOUNT=0 and QDCOUNT=1 ---
    try:
        pkt = DnsQuery.build("scea.com", qtype=QTYPE_A, txn_id=0xF214)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_nxdomain_counts", resp.rcode, 3, "RCODE")
        ok &= assert_eq(results, "tcp_nxdomain_counts", resp.ancount, 0, "ANCOUNT")
        ok &= assert_eq(results, "tcp_nxdomain_counts", resp.qdcount, 1, "QDCOUNT")
        ok &= assert_eq(results, "tcp_nxdomain_counts", resp.nscount, 1, "NSCOUNT")
        if ok:
            results.ok("tcp_nxdomain_counts")
    except Exception as e:
        results.fail("tcp_nxdomain_counts", str(e))

    # --- TCP: NOERROR response has correct section counts ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF215)
        resp = stq(pkt)
        ok = True
        ok &= assert_eq(results, "tcp_noerror_counts", resp.rcode, 0, "RCODE")
        ok &= assert_eq(results, "tcp_noerror_counts", resp.qdcount, 1, "QDCOUNT")
        ok &= assert_eq(results, "tcp_noerror_counts", resp.ancount, 1, "ANCOUNT")
        ok &= assert_eq(results, "tcp_noerror_counts", resp.nscount, 0, "NSCOUNT")
        ok &= assert_eq(results, "tcp_noerror_counts", resp.arcount, 0, "ARCOUNT")
        if ok:
            results.ok("tcp_noerror_counts")
    except Exception as e:
        results.fail("tcp_noerror_counts", str(e))

    # --- TCP: Z bits are zero (reserved, RFC 1035 §4.1.1) ---
    try:
        pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xF216)
        resp = stq(pkt)
        z_bit = (resp.flags >> 6) & 1
        if assert_eq(results, "tcp_z_bits_zero", z_bit, 0, "Z"):
            results.ok("tcp_z_bits_zero")
    except Exception as e:
        results.fail("tcp_z_bits_zero", str(e))


def main():
    binary = os.path.abspath(BINARY)
    zones = os.path.abspath(ZONES_FILE)

    if not os.path.isfile(binary):
        print(f"ERROR: Binary not found at {binary}")
        print("Build the project first: cmake -DCMAKE_BUILD_TYPE=Debug . && make")
        return 1

    if not os.path.isfile(zones):
        print(f"ERROR: Zones file not found at {zones}")
        return 1

    env = os.environ.copy()
    test_port = DNS_PORT

    print(f"Starting chukei-dns on {DNS_IP}:{test_port}...")

    proc = subprocess.Popen(
        [binary, "--zones", zones, "--dns-port", str(test_port), "--dns-ip", DNS_IP],
        cwd=os.path.dirname(zones),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(STARTUP_WAIT)

    if proc.poll() is not None:
        print(f"ERROR: Server exited immediately with code {proc.returncode}")
        return 1

    results = TestResults()

    print(f"Running integration tests against {DNS_IP}:{test_port}...")
    print("========================================")

    try:
        run_tests_with_port(results, test_port)
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # ========================================================================
    # LOG LEVEL OPTION TESTS
    # ========================================================================

    print("\nRunning --log-level tests...")
    print("========================================")

    # --- --log-level warn: server starts and responds normally ---
    try:
        warn_port = test_port + 1
        proc2 = subprocess.Popen(
            [binary, "--zones", zones, "--dns-port", str(warn_port), "--dns-ip", DNS_IP,
             "--log-level", "warn"],
            cwd=os.path.dirname(zones),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(STARTUP_WAIT)
        if proc2.poll() is not None:
            results.fail("log_level_warn_starts", f"Server exited with code {proc2.returncode}")
        else:
            try:
                pkt = DnsQuery.build("playstation.com", qtype=QTYPE_A, txn_id=0xE001)
                resp = send_query(pkt, DNS_IP, warn_port)
                if resp.rcode == 0 and resp.ancount == 1:
                    results.ok("log_level_warn_starts")
                else:
                    results.fail("log_level_warn_starts", f"unexpected response: rcode={resp.rcode}, ancount={resp.ancount}")
            except Exception as e:
                results.fail("log_level_warn_starts", str(e))
            finally:
                proc2.send_signal(signal.SIGTERM)
                try:
                    proc2.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc2.kill()
                    proc2.wait()
    except Exception as e:
        results.fail("log_level_warn_starts", str(e))

    # --- --log-level invalid: server exits with non-zero code ---
    try:
        proc3 = subprocess.Popen(
            [binary, "--zones", zones, "--dns-port", str(test_port + 2), "--dns-ip", DNS_IP,
             "--log-level", "invalid_level"],
            cwd=os.path.dirname(zones),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc3.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc3.kill()
            proc3.wait()
            results.fail("log_level_invalid_exits", "Server did not exit within timeout")
        else:
            if proc3.returncode != 0:
                results.ok("log_level_invalid_exits")
            else:
                results.fail("log_level_invalid_exits", f"Server exited with code 0, expected non-zero")
    except Exception as e:
        results.fail("log_level_invalid_exits", str(e))

    return results.summary()


if __name__ == "__main__":
    sys.exit(main())
