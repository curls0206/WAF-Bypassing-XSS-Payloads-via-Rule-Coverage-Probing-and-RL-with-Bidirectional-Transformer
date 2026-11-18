# logger.py
# 強化版 logger：同時支援 step-level 與 payload-session-level 記錄
import os
import logging
import json
from datetime import datetime
from threading import Lock
from typing import Optional, Dict, Any
from torch.utils.tensorboard import SummaryWriter

# -------------------------
# 目錄與檔案設置
# -------------------------
BASE_DIR = "res"
LOG_DIR = os.path.join(BASE_DIR, "logs")
PAYLOAD_LOG_DIR = os.path.join(BASE_DIR, "logs_payload")
TENSORBOARD_DIR = os.path.join(BASE_DIR, "tensorboard")
PAYLOAD_SESSIONS_FILE = os.path.join(PAYLOAD_LOG_DIR, "payload_sessions.jsonl")

for d in [LOG_DIR, PAYLOAD_LOG_DIR, TENSORBOARD_DIR]:
    os.makedirs(d, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
TRAIN_LOG_FILE = os.path.join(LOG_DIR, f"train_{timestamp}.log")
PAYLOAD_LOG_FILE = os.path.join(PAYLOAD_LOG_DIR, f"payload_{timestamp}.log")

# -------------------------
# 基本 logger 與 payload logger
# -------------------------
logging.basicConfig(
    filename=TRAIN_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%H:%M:%S"
)

payload_logger = logging.getLogger("payload_logger")
_payload_handler = logging.FileHandler(PAYLOAD_LOG_FILE, encoding="utf-8")
_payload_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%H:%M:%S"))
payload_logger.addHandler(_payload_handler)
payload_logger.setLevel(logging.INFO)

# TensorBoard writer
writer = SummaryWriter(log_dir=os.path.join(TENSORBOARD_DIR, f"tensorboard_{timestamp}"))

# Thread-safety for session writes
_session_lock = Lock()

# -------------------------
# In-memory payload session state
# -------------------------
# Current session structure:
# {
#   "id": <payload_id>,
#   "original": <original_payload>,
#   "steps": [ {step_info}, ... ],
#   "history": [original, step1_payload, ...],
#   "meta": { ... },
#   "started_at": <iso>,
# }
_current_session: Optional[Dict[str, Any]] = None
_last_session: Optional[Dict[str, Any]] = None   # ← 新增：記錄最近一次結束的 session

# -------------------------
# Step-level logging (unchanged behavior, improved formatting)
# -------------------------
def log_step(step: int, action: str, prob: float, last_prob: float,
             lev_sim: float, reward: float, success: bool):
    """
    Step-level compact logging and tensorboard metrics.
    - prob: model's XSS probability (lower is better)
    - success: bool, whether this step achieved bypass
    """
    delta = prob - last_prob
    logging.info(
        f"step={step:03d} | action={action:20s} | prob={prob:.4f} | "
        f"delta_prob={delta:+.4f} | lev_sim={lev_sim:.4f} | "
        f"reward={reward:+.4f} | success={success}"
    )

    writer.add_scalar("Step/Reward", reward, step)
    writer.add_scalar("Step/Prob", prob, step)
    writer.add_scalar("Step/Delta_Prob", delta, step)
    writer.add_scalar("Step/Levenshtein", lev_sim, step)
    writer.add_scalar("Step/Success_Flag", int(success), step)


# -------------------------
# Episode-level logging
# -------------------------
def log_episode(ep: int, total_reward: float, success: bool, steps: int, final_prob: Optional[float] = None):
    msg = (
        f"==== EP{ep:04d} End | total_reward={total_reward:+.4f} | "
        f"steps={steps:02d} | success={success} | "
    )
    if final_prob is not None:
        msg += f"final_prob={final_prob:.4f} ===="
    else:
        msg += "final_prob=N/A ===="

    logging.info(msg)

    writer.add_scalar("Episode/Total_Reward", total_reward, ep)
    writer.add_scalar("Episode/Steps", steps, ep)
    writer.add_scalar("Episode/Success", int(success), ep)
    if final_prob is not None:
        writer.add_scalar("Episode/Final_Prob", final_prob, ep)


# -------------------------
# Legacy payload logging (compact)
# -------------------------
def log_payload(payload: str, step: int, action_name: Optional[str] = None,
                prob: Optional[float] = None, lev_sim: Optional[float] = None,
                reward: Optional[float] = None, success: Optional[bool] = None,
                diff: Optional[str] = None):
    msg = f"step={step:03d} | action={action_name or 'N/A':20s}"
    if prob is not None:
        msg += f" | prob={prob:.4f}"
    if lev_sim is not None:
        msg += f" | lev_sim={lev_sim:.4f}"
    if reward is not None:
        msg += f" | reward={reward:+.4f}"
    if success is not None:
        msg += f" | success={success}"
    msg += f" | payload={payload}"
    payload_logger.info(msg)
    if diff:
        payload_logger.info(f"    Δ {diff}")


# -------------------------
# Payload-session API
# -------------------------
def start_payload_session(payload_id: str, original_payload: str, meta: Optional[dict] = None):
    """
    開始一個 payload 的 mutation session。
    - payload_id: 任意可辨識字串（例如 "seed_12" 或 timestamp）
    - original_payload: 原始 payload 字串
    - meta: 可選額外資訊（例如 seed index, filename, label 等）
    """
    global _current_session, _last_session
    with _session_lock:
        if _current_session is not None:
            # 若已有開啟的 session，先自動結束它（以防資源遺漏）
            end_payload_session(_current_session.get("id", "auto_end"), success=False, extra_info={"auto_end": True})
        _current_session = {
            "id": payload_id,
            "original": original_payload,
            "steps": [],
            "history": [original_payload],     # ← 追蹤 payload 演變
            "meta": meta or {},
            "started_at": datetime.now().isoformat()
        }
        payload_logger.info(f"[SESSION START] id={payload_id} | original={original_payload}")
        return _current_session


def record_payload_step(step: int, action_name: str, new_payload: str, prob: float,
                        lev_sim: float, reward: float, success: bool,
                        delta_prob: Optional[float] = None,
                        diff: Optional[str] = None):
    """
    在當前 session 中紀錄一個 step（會同時做 step-level & compact payload log）。
    - 若沒有 active session，會自動建立一個匿名 session（id=anon_<timestamp>）
    - 新增 diff：記錄本步 payload 與前一步的差異摘要
    """
    global _current_session
    with _session_lock:
        if _current_session is None:
            anon_id = f"anon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            start_payload_session(anon_id, original_payload=new_payload, meta={"auto_created": True})

        step_entry = {
            "step": int(step),
            "action": action_name,
            "payload": new_payload,
            "prob": float(prob),
            "lev_sim": float(lev_sim),
            "reward": float(reward),
            "success": bool(success),
            "ts": datetime.now().isoformat()
        }
        if delta_prob is not None:
            step_entry["delta_prob"] = float(delta_prob)
        if diff is not None:
            step_entry["diff"] = diff

        _current_session["steps"].append(step_entry)
        _current_session["history"].append(new_payload)   # ← 追加歷程

        # compact logging for immediate human readability
        log_payload(new_payload, step, action_name=action_name, prob=prob,
                    lev_sim=lev_sim, reward=reward, success=success, diff=diff)

        # also call log_step for tensorboard metrics
        last_prob = _current_session["steps"][-2]["prob"] if len(_current_session["steps"]) > 1 else prob
        log_step(step, action_name, prob, last_prob, lev_sim, reward, success)


def end_payload_session(payload_id: str, success: bool, extra_info: Optional[dict] = None):
    """
    結束當前 session，並把整個 session 以可讀方式寫入 payload log 檔，
    同時把一行 JSON 追加到 payload_sessions.jsonl（便於機器分析）。
    """
    global _current_session, _last_session
    with _session_lock:
        if _current_session is None:
            payload_logger.warning(f"end_payload_session called but no active session: id={payload_id}")
            return

        if _current_session.get("id") != payload_id:
            # If mismatch, still finalize current session but warn
            payload_logger.warning(f"end_payload_session id mismatch: asked={payload_id} current={_current_session.get('id')}")

        _current_session["ended_at"] = datetime.now().isoformat()
        _current_session["success"] = bool(success)
        if extra_info:
            _current_session["extra_info"] = extra_info

        # Write a readable block to payload log
        header = f"--- PAYLOAD_SESSION { _current_session['id'] } STARTED { _current_session['started_at'] } ---"
        payload_logger.info(header)
        payload_logger.info(f"original: { _current_session['original'] }")
        if _current_session.get("meta"):
            payload_logger.info(f"meta: {json.dumps(_current_session['meta'], ensure_ascii=False)}")
        for st in _current_session["steps"]:
            s = (f"step={st['step']:03d} | action={st['action']:20s} | prob={st['prob']:.4f} "
                 f"| lev_sim={st['lev_sim']:.4f} | reward={st['reward']:+.4f} | success={st['success']} "
                 f"| payload={st['payload']}")
            payload_logger.info(s)
            if "diff" in st and st["diff"]:
                payload_logger.info(f"    Δ {st['diff']}")
        footer = f"--- PAYLOAD_SESSION { _current_session['id'] } ENDED { _current_session['ended_at'] } SUCCESS={_current_session['success']} ---"
        payload_logger.info(footer)

        # Append JSONL record for machine consumption（包含完整 history 與 steps）
        jsonl_rec = dict(_current_session)
        jsonl_rec["payload_history"] = _current_session.get("history", [])
        try:
            with open(PAYLOAD_SESSIONS_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(jsonl_rec, ensure_ascii=False) + "\n")
        except Exception as e:
            payload_logger.error(f"Failed to write payload session jsonl: {e}")

        # 把這個 session 存成「最後一次結束的 session」
        _last_session = _current_session

        # Clear current session
        _current_session = None


# -------------------------
# Utility & query
# -------------------------
def get_last_payload_session():
    """
    回傳最近一次結束的 payload session（給訓練程式印變異過程用）
    """
    global _last_session
    return _last_session


def close_logger():
    logging.info("=== Logger Closed ===")
    writer.close()
    # close payload handlers
    for h in list(payload_logger.handlers):
        try:
            h.close()
            payload_logger.removeHandler(h)
        except Exception:
            pass


# -------------------------
# Example usage (for quick manual test)
# -------------------------
if __name__ == "__main__":
    start_payload_session("test_001", "<script>alert(1)</script>", meta={"seed_idx": 0})
    record_payload_step(1, "insert_char", "<scri<pt>alert(1)</script>", 0.92, 0.98, -0.1, False, diff="+ <pt>")
    record_payload_step(2, "replace", "<scri'pt>alert(1)</script>", 0.85, 0.97, -0.05, False, diff="- <pt> | + '")
    record_payload_step(3, "encode", "%3Cscript%3Ealert(1)%3C%2Fscript%3sE", 0.12, 0.80, 10.0, True, diff="+ %3C...%3E")
    end_payload_session("test_001", success=True, extra_info={"note": "auto test"})
    sess = get_last_payload_session()
    print("[TEST LAST SESSION]", sess is not None)
    close_logger()
