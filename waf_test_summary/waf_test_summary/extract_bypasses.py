import json

with open('waf_test_results.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

bypasses = [p for p in data if p['label'] == 'valid' and p.get('waf_passed') == True]

with open('bypassed_payloads.txt', 'w', encoding='utf-8') as out:
    for p in bypasses:
        out.write(f"[{p['encoding_type']}] {p.get('scenario', '')}\n")
        out.write(f"PAYLOAD: {p['payload']}\n")
        out.write("-" * 80 + "\n")

print(f"Extraction complete! Found {len(bypasses)} successful bypasses.")
