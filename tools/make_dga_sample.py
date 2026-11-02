# -*- coding: utf-8 -*-
"""DGA 전용 합성 pcap (QA 2차 10번째 샘플용).

공개 DGA 전용 캡처를 구하지 못해 생성한다. 감염 PC가 무작위 도메인을
대량 질의해 NXDOMAIN 을 받다가 하나가 살아 있는 C2 로 해석되는 흐름이고,
정상 도메인 질의를 대조군으로 섞는다. 실제 악성코드는 없다.

사용: python tools/make_dga_sample.py <출력.pcap>
"""
import os
import random
import string
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapfor import craft
from pcapfor.pcapio import write_pcap

rng = random.Random(2026)
victim, resolver = "10.10.5.23", "10.10.5.1"
t = 1761000000.0
pkts = []


def q(name, ts, txid, rcode=0, ip=None):
    port = 50000 + txid % 10000
    craft.udp_packet(pkts, ts, victim, resolver, port, 53, craft.dns_query(name, txid=txid))
    craft.udp_packet(pkts, ts + 0.03, resolver, victim, 53, port,
                     craft.dns_response(name, rcode=rcode, answer_ip=ip, txid=txid))


for i, name in enumerate(["www.naver.com", "www.google.com", "update.microsoft.com"]):
    q(name, t + i, 0x100 + i, ip="93.184.216.34")
for i in range(40):  # 무작위 생성 도메인 → 존재하지 않음
    label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(12, 18)))
    q(f"{label}.{rng.choice(['com', 'net', 'info'])}", t + 10 + i * 0.25, 0x200 + i, rcode=3)
q("k3h9xq2vmp7ztr.com", t + 25, 0x300, ip="203.0.113.77")  # 살아 있는 C2 도메인

write_pcap(sys.argv[1], pkts)
print(f"{sys.argv[1]}: {len(pkts)} packets")
