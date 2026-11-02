# -*- coding: utf-8 -*-
"""QA용 CLI 출력을 터미널 스타일 HTML로 변환 (스크린샷 전 단계).

사용: python qa_cli_shots.py <raw 폴더> <키=명령 표시용 파일명> ...
출력: <raw>/<키>_cli.html, 그리고 키별 권장 캡처 높이(px)를 표준출력으로
"""
import html
import io
import sys

TPL = """<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#0c1017;font-family:Consolas,'Malgun Gothic',monospace;font-size:14px}}
.bar{{background:#1b2430;color:#9fb0c5;padding:8px 14px;font-size:12.5px;border-bottom:1px solid #2a3240}}
.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}}
pre{{color:#d8e6f5;padding:12px 18px;margin:0;line-height:1.5;white-space:pre-wrap}}
.cmd{{color:#63d0a4}}
.sev-c{{color:#ff8a86;font-weight:bold}} .sev-h{{color:#ffb27d;font-weight:bold}} .sev-m{{color:#ffe082;font-weight:bold}}
</style></head><body>
<div class="bar"><span class="dot" style="background:#e05252"></span><span class="dot" style="background:#e8b33a"></span><span class="dot" style="background:#63d0a4"></span>pcap for · CLI</div>
<pre><span class="cmd">PS C:\\pcap-for&gt; {cmd}</span>
{body}</pre></body></html>"""

raw = sys.argv[1]
for arg in sys.argv[2:]:
    key, shown = arg.split("=", 1)
    with io.open(rf"{raw}\{key}_cli.txt", encoding="utf-8") as f:
        text = f.read()
    body = html.escape(text)
    for ko, cls in (("심각", "c"), ("높음", "h"), ("중간", "m")):
        body = body.replace(f"({ko}/", f'(<span class="sev-{cls}">{ko}</span>/')
    with io.open(rf"{raw}\{key}_cli.html", "w", encoding="utf-8") as f:
        f.write(TPL.format(cmd=html.escape(f"python -m pcapfor {shown} -v"), body=body))
    # 1150px 폭에서 줄바꿈되는 긴 줄까지 감안한 높이 추정
    rows = sum(max(1, -(-len(line) // 118)) for line in text.splitlines()) + 2
    print(f"{key} {70 + rows * 21}")
