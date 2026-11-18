#!/usr/bin/env python3
"""
WAF Testing Script - XSS Payloads vs ModSecurity CRS
=====================================================
Sends all payloads from xss_dataset_labeled.json to a local WAF
endpoint and records which are blocked (403) vs allowed (200/other).

Outputs:
  1. waf_test_results.json   - per-payload result details
  2. waf_test_summary.txt    - confusion matrix, accuracy, metrics

Usage: python test_xss_against_waf.py [--url http://localhost] [--delay 0.05]
Requirements: Python 3.7+ (standard library only)
"""

import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import ssl
import argparse
from datetime import datetime

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def send_payload(base_url, payload, method="GET", timeout=10):
    """Send a payload to the WAF and return (status_code, blocked)."""
    try:
        if method == "GET":
            encoded = urllib.parse.quote(payload, safe='')
            url = f"{base_url}/?input={encoded}"
            req = urllib.request.Request(url, method="GET")
        else:  # POST
            data = urllib.parse.urlencode({"input": payload}).encode('utf-8')
            url = base_url + "/"
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XSS-Research-Scanner/1.0")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return response.getcode(), False
    except urllib.error.HTTPError as e:
        return e.code, (e.code == 403)
    except urllib.error.URLError as e:
        return -1, None
    except Exception as e:
        return -1, None


def check_waf_alive(base_url):
    """Check if WAF is responding."""
    try:
        req = urllib.request.Request(f"{base_url}/", method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 HealthCheck")
        response = urllib.request.urlopen(req, timeout=5)
        return True
    except urllib.error.HTTPError:
        return True  # WAF responded with error, but it's alive
    except Exception:
        return False


def run_tests(base_url, dataset_path, delay=0.05):
    """Run all payloads against the WAF."""
    with open(dataset_path, 'r', encoding='utf-8') as f:
        payloads = json.load(f)

    total = len(payloads)
    results = []
    blocked_count = 0
    passed_count = 0
    error_count = 0

    # Confusion matrix counters
    # For malicious payloads (label=valid + waf_bypass=True):
    #   WAF blocks = True Positive (WAF caught it despite bypass attempt)
    #   WAF passes = False Negative (bypass succeeded, WAF missed)
    # For malicious payloads (label=valid + waf_bypass=False):
    #   WAF blocks = True Positive
    #   WAF passes = False Negative
    # For benign/invalid payloads (label=invalid):
    #   WAF blocks = False Positive (WAF false alarm)
    #   WAF passes = True Negative (correctly allowed)

    tp = 0  # WAF blocks malicious payload (correct)
    tn = 0  # WAF passes benign/invalid payload (correct)
    fp = 0  # WAF blocks benign/invalid payload (false alarm)
    fn = 0  # WAF passes malicious payload (missed)

    print(f"\n{'=' * 70}")
    print(f"  WAF Testing: {total} payloads against {base_url}")
    print(f"  PARANOIA Level 2 | ModSecurity CRS")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 70}\n")

    for i, entry in enumerate(payloads):
        payload = entry["payload"]
        label = entry["label"]
        payload_id = entry["id"]

        # Send GET request
        get_status, get_blocked = send_payload(base_url, payload, "GET")

        # Send POST request
        post_status, post_blocked = send_payload(base_url, payload, "POST")

        # A payload is considered "blocked" if EITHER method returns 403
        blocked = (get_blocked is True) or (post_blocked is True)
        # A payload "passed" only if BOTH methods allowed it
        passed = (get_blocked is False) and (post_blocked is False)

        if blocked:
            blocked_count += 1
        elif passed:
            passed_count += 1
        else:
            error_count += 1

        # Confusion matrix (from WAF perspective: is it malicious?)
        is_malicious = (label == "valid")  # valid=can execute=malicious payload

        if blocked is True:
            if is_malicious:
                tp += 1  # Correctly blocked malicious
            else:
                fp += 1  # Incorrectly blocked benign
        elif passed is True:
            if is_malicious:
                fn += 1  # Missed malicious (bad)
            else:
                tn += 1  # Correctly passed benign
        # errors are not counted in confusion matrix

        result_entry = {
            "id": payload_id,
            "payload": payload,
            "encoding_type": entry["encoding_type"],
            "label": label,
            "waf_bypass": entry.get("waf_bypass", False),
            "scenario": entry["scenario"],
            "get_status": get_status,
            "post_status": post_status,
            "waf_blocked": blocked,
            "waf_passed": passed,
            "detection_correct": (blocked and is_malicious) or (passed and not is_malicious),
        }
        results.append(result_entry)

        # Progress indicator
        status_icon = "🛡️ BLOCKED" if blocked else ("✅ PASSED" if passed else "⚠️ ERROR")
        correct_icon = "✓" if result_entry["detection_correct"] else "✗"
        if (i + 1) % 25 == 0 or (i + 1) == total:
            pct = (i + 1) / total * 100
            print(f"  [{i+1:>4}/{total}] ({pct:5.1f}%) | Blocked: {blocked_count} | Passed: {passed_count} | Errors: {error_count}")

        time.sleep(delay)

    return results, {
        "total": total,
        "blocked": blocked_count,
        "passed": passed_count,
        "errors": error_count,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn
    }


def write_results(results, stats, base_url):
    """Write test results to files."""
    results_path = os.path.join(OUTPUT_DIR, "waf_test_results.json")
    summary_path = os.path.join(OUTPUT_DIR, "waf_test_summary.txt")

    # Write detailed results
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    # Calculate metrics
    tp, tn, fp, fn = stats["tp"], stats["tn"], stats["fp"], stats["fn"]
    total_classified = tp + tn + fp + fn

    accuracy = (tp + tn) / total_classified * 100 if total_classified > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) * 100 if (fn + tp) > 0 else 0

    # Breakdown by encoding type
    enc_breakdown = {}
    for r in results:
        et = r["encoding_type"]
        if et not in enc_breakdown:
            enc_breakdown[et] = {"total": 0, "blocked": 0, "passed": 0, "correct": 0}
        enc_breakdown[et]["total"] += 1
        if r["waf_blocked"]:
            enc_breakdown[et]["blocked"] += 1
        elif r["waf_passed"]:
            enc_breakdown[et]["passed"] += 1
        if r.get("detection_correct"):
            enc_breakdown[et]["correct"] += 1

    # Breakdown by scenario
    scn_breakdown = {}
    for r in results:
        sc = r["scenario"]
        if sc not in scn_breakdown:
            scn_breakdown[sc] = {"total": 0, "blocked": 0, "passed": 0}
        scn_breakdown[sc]["total"] += 1
        if r["waf_blocked"]:
            scn_breakdown[sc]["blocked"] += 1
        elif r["waf_passed"]:
            scn_breakdown[sc]["passed"] += 1

    # Find bypassed payloads (malicious payloads that got through)
    bypassed = [r for r in results if r["label"] == "valid" and r["waf_passed"]]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = f"""{'=' * 70}
  WAF TEST RESULTS SUMMARY
  ModSecurity CRS - PARANOIA Level 2
  Target: {base_url}
  Time: {timestamp}
{'=' * 70}

OVERALL STATISTICS
{'─' * 40}
  Total Payloads Tested:  {stats['total']}
  Blocked by WAF (403):   {stats['blocked']}
  Passed WAF (200):       {stats['passed']}
  Errors (timeout/etc):   {stats['errors']}
  Block Rate:             {stats['blocked'] / stats['total'] * 100:.1f}%

CONFUSION MATRIX (WAF as Malicious Detector)
{'─' * 40}
                    Predicted
                  Blocked  Passed
  Actual Malicious   {tp:>5}   {fn:>5}   (TP / FN)
  Actual Benign      {fp:>5}   {tn:>5}   (FP / TN)

METRICS
{'─' * 40}
  Accuracy:           {accuracy:.1f}%
  Precision:          {precision:.1f}%
  Recall (Detection): {recall:.1f}%
  F1 Score:           {f1:.1f}%
  False Positive Rate:{fpr:.1f}%
  False Negative Rate:{fnr:.1f}%

DETECTION BY ENCODING TYPE
{'─' * 70}
  {'Encoding Type':<35} {'Total':>5} {'Block':>6} {'Pass':>6} {'Block%':>7} {'Acc%':>6}
  {'─' * 65}
"""

    for et, counts in sorted(enc_breakdown.items()):
        block_pct = counts["blocked"] / counts["total"] * 100 if counts["total"] > 0 else 0
        acc_pct = counts["correct"] / counts["total"] * 100 if counts["total"] > 0 else 0
        summary += f"  {et:<35} {counts['total']:>5} {counts['blocked']:>6} {counts['passed']:>6} {block_pct:>6.1f}% {acc_pct:>5.1f}%\n"

    summary += f"""
DETECTION BY SCENARIO
{'─' * 70}
  {'Scenario':<30} {'Total':>5} {'Blocked':>8} {'Passed':>8} {'Block%':>7}
  {'─' * 60}
"""

    for sc, counts in sorted(scn_breakdown.items()):
        block_pct = counts["blocked"] / counts["total"] * 100 if counts["total"] > 0 else 0
        summary += f"  {sc:<30} {counts['total']:>5} {counts['blocked']:>8} {counts['passed']:>8} {block_pct:>6.1f}%\n"

    summary += f"""
BYPASSED PAYLOADS (Malicious that passed WAF)
{'─' * 70}
  Total bypassed: {len(bypassed)} / {sum(1 for r in results if r['label']=='valid')} malicious payloads
"""

    for r in bypassed[:30]:  # Show first 30
        p = r["payload"][:80] + ("..." if len(r["payload"]) > 80 else "")
        summary += f"  [{r['id']:>4}] [{r['encoding_type']:<25}] {p}\n"

    if len(bypassed) > 30:
        summary += f"  ... and {len(bypassed) - 30} more (see waf_test_results.json)\n"

    summary += f"\n{'=' * 70}\n"

    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(summary)

    print(summary)
    print(f"\n  Results: {results_path}")
    print(f"  Summary: {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Test XSS payloads against WAF")
    parser.add_argument("--url", default="http://localhost", help="WAF base URL")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between requests (seconds)")
    parser.add_argument("--dataset", default=os.path.join(OUTPUT_DIR, "xss_dataset_labeled.json"),
                        help="Path to labeled dataset JSON")
    args = parser.parse_args()

    print(f"\n  Checking WAF at {args.url} ...")
    if not check_waf_alive(args.url):
        print(f"  ❌ WAF not responding at {args.url}")
        print(f"  Please start the WAF container first:")
        print(f"    cd modsecurity-crs-docker-main-20260323T145056Z-1-001\\modsecurity-crs-docker-main")
        print(f"    docker compose up -d")
        print(f"    # Wait ~10 seconds for container to start")
        sys.exit(1)

    print(f"  ✅ WAF is responding!")

    if not os.path.exists(args.dataset):
        print(f"  ❌ Dataset not found: {args.dataset}")
        print(f"  Run generate_xss_payloads_extended.py first.")
        sys.exit(1)

    results, stats = run_tests(args.url, args.dataset, args.delay)
    write_results(results, stats, args.url)


if __name__ == "__main__":
    main()
