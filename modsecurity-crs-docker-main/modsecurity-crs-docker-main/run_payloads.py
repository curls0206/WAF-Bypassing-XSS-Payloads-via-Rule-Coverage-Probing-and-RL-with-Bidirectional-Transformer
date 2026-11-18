import os
import subprocess

INPUT_FILE = "bypass_payloads.txt"
OUTPUT_FILE = "bypass.txt"
BODY_FILE = "body.txt"
URL = "http://localhost:8088/comment"


def clean_payload(line: str) -> str:
    line = line.strip()

    # 移除外層雙引號
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1]

    return line.strip()


def load_existing_bypass(output_file: str) -> set[str]:
    if not os.path.exists(output_file):
        return set()

    existing = set()
    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            payload = line.rstrip("\n").rstrip("\r")
            if payload:
                existing.add(payload)

    return existing


def run_payload(payload: str) -> str:
    # 寫入 body.txt
    with open(BODY_FILE, "w", encoding="utf-8") as f:
        f.write("message=" + payload)

    cmd = [
        "curl.exe",
        "-i",
        "-X", "POST",
        URL,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "--data-binary", f"@{BODY_FILE}"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    return result.stdout


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] 找不到輸入檔案: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    existing_bypass = load_existing_bypass(OUTPUT_FILE)

    bypass_this_run = []
    new_bypass = []

    for i, line in enumerate(lines):
        payload = clean_payload(line)

        if not payload:
            continue

        print(f"\n[TEST {i}] {payload[:80]}...")

        output = run_payload(payload)

        if "HTTP/1.1 200" in output:
            print("✅ BYPASS")
            bypass_this_run.append(payload)

            if payload not in existing_bypass:
                new_bypass.append(payload)
                existing_bypass.add(payload)

        elif "HTTP/1.1 403" in output:
            print("❌ BLOCKED")
        else:
            print("⚠ UNKNOWN")

    if new_bypass:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            for p in new_bypass:
                f.write(p + "\n")

    print(f"\nDone.")
    print(f"[+] 本輪 bypass 數: {len(bypass_this_run)}")
    print(f"[+] 新增到 {OUTPUT_FILE} 的數量: {len(new_bypass)}")
    print(f"[+] 已存在而略過重複的數量: {len(bypass_this_run) - len(new_bypass)}")


if __name__ == "__main__":
    main()