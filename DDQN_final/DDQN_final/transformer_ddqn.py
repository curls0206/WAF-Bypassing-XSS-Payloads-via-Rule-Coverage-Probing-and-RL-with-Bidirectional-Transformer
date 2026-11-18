#!/usr/bin/env python3
import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Optional

import torch

from transformer_env import TransformerEnv, EnvHyper
from ddqn_agent import DDQNAgent
from logger import get_last_payload_session
def parse_args():
    base_dir = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description="Train DDQN agent against Transformer WAF environment.")
    p.add_argument("--episodes", type=int, default=10, help="Number of training episodes.")
    p.add_argument("--eval_episodes", type=int, default=0, help="Evaluation episodes after training.")
    p.add_argument(
        "--html_url",
        type=str,
        default="http://127.0.0.1:8081/vulnerabilities/xss_r/",
        help="Target HTML page used in browser validation.",
    )
    p.add_argument("--keras_model", type=str, default=str(base_dir / "BestModel_Transformer.keras"),
                   help="Path to Keras .keras weights for the transformer detector.")
    p.add_argument("--max_steps", type=int, default=10, help="Max steps per episode.")

    p.add_argument("--prob_success_threshold", type=float, default=0.1,
                   help="Bypass success if transformer prob <= this threshold.")
    p.add_argument("--success_mode", type=str, default="model_browser_modsec",
                   choices=["model_only", "model_and_browser", "model_browser_modsec"],
                   help="Success criterion mode.")
    p.add_argument("--min_mutation_steps_for_success", type=int, default=1,
                   help="Require at least this many mutation steps before a run can count as success.")
    p.add_argument("--allow_initial_success", action="store_true",
                   help="Allow episodes that already bypass at reset instead of resampling failing seeds.")
    p.add_argument("--browser_timeout_s", type=float, default=5.0,
                   help="Timeout in seconds for Playwright validation.")
    p.add_argument("--browser_param_name", type=str, default="name",
                   help="Parameter name used for browser-side payload injection.")
    p.add_argument("--dvwa_username", type=str, default="admin",
                   help="DVWA username used when html_url points to DVWA.")
    p.add_argument("--dvwa_password", type=str, default="password",
                   help="DVWA password used when html_url points to DVWA.")
    p.add_argument("--dvwa_security_level", type=str, default="low",
                   help="DVWA security level to set before reflected-XSS testing.")
    p.add_argument("--disable_browser_check", action="store_true",
                   help="Disable Playwright validation.")
    p.add_argument("--modsec_url", type=str, default="http://localhost/vulnerabilities/xss_r/",
                   help="ModSecurity protected endpoint used during training.")
    p.add_argument("--modsec_param_name", type=str, default="name",
                   help="Parameter name used for ModSecurity testing.")
    p.add_argument("--modsec_timeout_s", type=float, default=10.0,
                   help="Timeout in seconds for ModSecurity validation.")
    p.add_argument("--modsec_success_mode", type=str, default="not_blocked",
                   choices=["not_blocked", "not_blocked_and_crs"],
                   help="Use plain not-blocked or combine it with CRS-count threshold.")
    p.add_argument("--max_triggered_crs_rules", type=int, default=2,
                   help="A payload succeeds only if triggered CRS rule count is <= this value.")
    p.add_argument("--disable_modsec_check", action="store_true",
                   help="Disable ModSecurity validation.")

    p.add_argument("--reward_success", type=float, default=10.0, help="Reward when bypass succeeds.")
    p.add_argument("--reward_step_penalty", type=float, default=-0.1, help="Per-step penalty.")
    p.add_argument("--reward_delta_weight", type=float, default=1.0,
                   help="Weight for positive probability drop (prev_prob - curr_prob).")
    p.add_argument("--reward_delta_neg_weight", type=float, default=0.3,
                   help="Penalty weight for probability increase (curr_prob - prev_prob).")
    p.add_argument("--reward_margin_weight", type=float, default=0.5,
                   help="Weight for margin reward max(threshold - curr_prob, 0).")
    p.add_argument("--reward_len_weight", type=float, default=-0.001,
                   help="Weight for payload length penalty.")
    p.add_argument("--reward_lev_weight", type=float, default=0.2,
                   help="Weight for payload similarity reward (lev_sim).")
    p.add_argument("--reward_no_change", type=float, default=-0.05,
                   help="Extra penalty when payload or probability barely changes.")
    p.add_argument("--tiny_change_eps", type=float, default=1e-4,
                   help="Threshold for considering probability change as tiny.")

    p.add_argument("--log_dir", type=str, default=str(base_dir / "runs" / "transformer_ddqn"),
                   help="Directory for episode stats JSONL output.")
    p.add_argument("--save_path", type=str, default="", help="Path to save the trained agent (Torch state_dict).")
    p.add_argument("--seed_payloads", type=str, default=str(base_dir / "payloads.txt"),
                   help="Optional text file: one seed payload per line.")
    p.add_argument("--success_payloads_txt", type=str, default=str(base_dir / "success_payloads_transformer.txt"),
                   help="Output txt for payloads that succeed after mutation.")
    p.add_argument("--device", type=str, default="auto", choices=["auto", "cpu", "cuda"],
                   help="Torch device override. 'auto' picks cuda if available.")
    return p.parse_args()


def load_seed_payloads(path: str) -> Optional[List[str]]:
    if not path:
        return None
    f = Path(path)
    if not f.exists():
        print(f"[WARN] seed_payloads file not found: {path}", file=sys.stderr)
        return None
    out: List[str] = []
    for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln2 = ln.strip()
        if not ln2:
            continue
        try:
            decoded = json.loads(ln2)
            out.append(decoded if isinstance(decoded, str) else ln2)
        except Exception:
            out.append(ln2)
    return out or None


def main():
    args = parse_args()

    device = torch.device("cuda" if (args.device == "auto" and torch.cuda.is_available()) else args.device if args.device != "auto" else "cpu")

    Path(args.log_dir).mkdir(parents=True, exist_ok=True)
    success_payloads_path = Path(args.success_payloads_txt)
    success_payloads_path.parent.mkdir(parents=True, exist_ok=True)

    env_h = EnvHyper(
        max_steps_per_episode=args.max_steps,
        html_url=args.html_url,
        keras_model_path=args.keras_model,
        max_len=600,
        R_success=args.reward_success,
        R_step_penalty=args.reward_step_penalty,
        R_syntax_fail=-5.0,
        w_delta=args.reward_delta_weight,
        w_delta_neg=args.reward_delta_neg_weight,
        w_margin=args.reward_margin_weight,
        w_len=args.reward_len_weight,
        w_lev=args.reward_lev_weight,
        R_no_change=args.reward_no_change,
        tiny_change_eps=args.tiny_change_eps,
        prob_success_threshold=args.prob_success_threshold,
        success_mode=args.success_mode,
        min_mutation_steps_for_success=args.min_mutation_steps_for_success,
        require_initial_failure=(not args.allow_initial_success),
        enable_browser_check=(not args.disable_browser_check),
        browser_timeout_s=args.browser_timeout_s,
        browser_param_name=args.browser_param_name,
        dvwa_username=args.dvwa_username,
        dvwa_password=args.dvwa_password,
        dvwa_security_level=args.dvwa_security_level,
        enable_modsec_check=(not args.disable_modsec_check),
        modsec_url=args.modsec_url,
        modsec_param_name=args.modsec_param_name,
        modsec_timeout_s=args.modsec_timeout_s,
        modsec_success_mode=args.modsec_success_mode,
        max_triggered_crs_rules=args.max_triggered_crs_rules,
    )
    seed_payloads = load_seed_payloads(args.seed_payloads)

    env = TransformerEnv(env_hyper=env_h, seed_payloads=seed_payloads)

    obs_dim = env.obs_dim
    n_actions = env.action_space_n
    agent = DDQNAgent(
        obs_dim=obs_dim,
        n_actions=n_actions,
        device=device,
        hidden_dim=256,
        lr=1e-4,
        gamma=0.99,
        buffer_size=20000,
        batch_size=64,
        target_update_freq=500,
        min_replay_size=500,
        eps_start=1.0,
        eps_end=0.10,
        eps_decay_episodes=800,
        tau=1.0,
    )

    stats = []
    initial_success_count = 0
    mutated_success_count = 0
    valid_start_count = 0
    goal_success_count = 0
    success_payloads: List[str] = []

    try:
        for ep in range(args.episodes):
            print(f"[EPISODE] {ep + 1}/{args.episodes}")
            s = agent.train_one_episode(env, episode_idx=ep, max_steps=args.max_steps, render=False)
            stats.append(s)
            if s.get("initial_success", False):
                initial_success_count += 1
            if s.get("mutated_success", False):
                mutated_success_count += 1
            if s.get("valid_start", False):
                valid_start_count += 1
            if s.get("goal_success", False):
                goal_success_count += 1

            sess = get_last_payload_session()
            if sess is None:
                continue
            final_payload = sess.get("history", [None])[-1]
            if s.get("mutated_success", False) and final_payload:
                success_payloads.append(str(final_payload))

    finally:
        env.close()

    if args.save_path:
        Path(os.path.dirname(args.save_path) or ".").mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "state_dict": agent.online_net.state_dict(),
                "obs_dim": obs_dim,
                "n_actions": n_actions,
                "config": {
                    "hidden_dim": 256,
                    "lr": 1e-4,
                    "gamma": 0.99,
                    "buffer_size": 20000,
                    "batch_size": 64,
                },
            },
            args.save_path,
        )
        print(f"[INFO] Saved model to {args.save_path}")

    if args.eval_episodes > 0:
        env2 = TransformerEnv(env_hyper=env_h, seed_payloads=seed_payloads)
        try:
            agent.evaluate(env2, n_episodes=args.eval_episodes, max_steps=args.max_steps)
        finally:
            env2.close()

    stats_path = Path(args.log_dir) / "train_stats.jsonl"
    with open(stats_path, "w", encoding="utf-8") as f:
        for s in stats:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"[INFO] Wrote episode stats to {stats_path}")

    unique_payloads = list(dict.fromkeys(success_payloads))
    if unique_payloads:
        with open(success_payloads_path, "a", encoding="utf-8") as f:
            for p in unique_payloads:
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
    print(f"[INFO] Appended {len(unique_payloads)} mutated-success payload(s) to {success_payloads_path}")

    print(
        f"[SUMMARY] success={sum(1 for s in stats if s.get('success'))}/{len(stats)} "
        f"initial_success={initial_success_count}/{len(stats)} "
        f"mutated_success={mutated_success_count}/{len(stats)} "
        f"transformer_pass={sum(1 for s in stats if s.get('transformer_pass'))}/{len(stats)} "
        f"playwright_pass={sum(1 for s in stats if s.get('playwright_pass'))}/{len(stats)} "
        f"modsec_pass={sum(1 for s in stats if s.get('modsec_pass'))}/{len(stats)} "
        f"goal_success={goal_success_count}/{max(1, valid_start_count)} "
        f"valid_starts={valid_start_count}/{len(stats)}"
    )


if __name__ == "__main__":
    main()
