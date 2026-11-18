from __future__ import annotations

import collections
import random
from typing import Any, Dict, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim


class DuelingDQN(nn.Module):
    def __init__(self, input_dim: int, n_actions: int, hidden_dim: int = 256):
        super().__init__()
        self.feature = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
        )
        self.value_stream = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
        )
        self.adv_stream = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, n_actions),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        f = self.feature(x)
        v = self.value_stream(f)
        a = self.adv_stream(f)
        return v + a - a.mean(dim=1, keepdim=True)


Transition = collections.namedtuple(
    "Transition", ["state", "action", "reward", "next_state", "done"]
)


class ReplayBuffer:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.buffer = collections.deque(maxlen=capacity)

    def push(self, *args):
        self.buffer.append(Transition(*args))

    def sample(self, batch_size: int) -> Transition:
        batch = random.sample(self.buffer, batch_size)
        return Transition(*zip(*batch))

    def __len__(self) -> int:
        return len(self.buffer)


class DDQNAgent:
    def __init__(
        self,
        obs_dim: int,
        n_actions: int,
        device: Optional[torch.device] = None,
        hidden_dim: int = 256,
        lr: float = 1e-4,
        gamma: float = 0.99,
        buffer_size: int = 20000,
        batch_size: int = 64,
        target_update_freq: int = 500,
        min_replay_size: int = 500,
        eps_start: float = 1.0,
        eps_end: float = 0.10,
        eps_decay_episodes: int = 800,
        tau: float = 1.0,
    ):
        self.device = device or (torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu"))
        self.obs_dim = obs_dim
        self.n_actions = n_actions

        self.online_net = DuelingDQN(obs_dim, n_actions, hidden_dim).to(self.device)
        self.target_net = DuelingDQN(obs_dim, n_actions, hidden_dim).to(self.device)
        self.target_net.load_state_dict(self.online_net.state_dict())

        self.optimizer = optim.Adam(self.online_net.parameters(), lr=lr)
        self.gamma = gamma

        self.replay = ReplayBuffer(buffer_size)
        self.batch_size = batch_size
        self.min_replay_size = min_replay_size
        self.target_update_freq = target_update_freq
        self.tau = tau

        self.eps_start = eps_start
        self.eps_end = eps_end
        self.eps_decay_episodes = max(1, eps_decay_episodes)
        self.epsilon = eps_start

        self.train_steps = 0
        self.target_updates = 0

    def act(self, state: np.ndarray, eval_mode: bool = False) -> int:
        if (not eval_mode) and (random.random() < self.epsilon):
            return random.randrange(self.n_actions)

        self.online_net.eval()
        with torch.no_grad():
            s = torch.tensor(state, dtype=torch.float32, device=self.device).unsqueeze(0)
            q = self.online_net(s)
            action = int(torch.argmax(q, dim=1).item())
        self.online_net.train()
        return action

    def remember(self, state, action, reward, next_state, done):
        self.replay.push(state, action, reward, next_state, done)

    def update_target(self):
        if self.tau >= 1.0:
            self.target_net.load_state_dict(self.online_net.state_dict())
        else:
            for p, tp in zip(self.online_net.parameters(), self.target_net.parameters()):
                tp.data.copy_(tp.data * (1.0 - self.tau) + p.data * self.tau)

    def train_step(self) -> Optional[float]:
        if len(self.replay) < self.min_replay_size:
            return None

        batch = self.replay.sample(self.batch_size)
        states = torch.tensor(np.array(batch.state), dtype=torch.float32, device=self.device)
        actions = torch.tensor(batch.action, dtype=torch.long, device=self.device).unsqueeze(1)
        rewards = torch.tensor(batch.reward, dtype=torch.float32, device=self.device).unsqueeze(1)
        next_states = torch.tensor(np.array(batch.next_state), dtype=torch.float32, device=self.device)
        dones = torch.tensor(batch.done, dtype=torch.float32, device=self.device).unsqueeze(1)

        q = self.online_net(states).gather(1, actions)

        with torch.no_grad():
            next_q_online = self.online_net(next_states)
            next_actions = torch.argmax(next_q_online, dim=1, keepdim=True)
            next_q_target = self.target_net(next_states)
            next_max = next_q_target.gather(1, next_actions)
            target = rewards + (1.0 - dones) * (self.gamma * next_max)

        loss = nn.functional.mse_loss(q, target)

        self.optimizer.zero_grad()
        loss.backward()
        nn.utils.clip_grad_norm_(self.online_net.parameters(), 10.0)
        self.optimizer.step()

        self.train_steps += 1
        if self.train_steps % self.target_update_freq == 0:
            self.update_target()
            self.target_updates += 1

        return float(loss.item())

    def decay_epsilon(self, episode_idx: int):
        frac = min(1.0, episode_idx / float(self.eps_decay_episodes))
        self.epsilon = self.eps_start + frac * (self.eps_end - self.eps_start)

    @staticmethod
    def _is_success(info: Dict[str, Any], env) -> bool:
        if "success" in info:
            return bool(info["success"])
        prob = info.get("prob", None)
        if prob is None:
            return False
        th = getattr(getattr(env, "env", env), "threshold", 0.5)
        try:
            return float(prob) < float(th)
        except Exception:
            return False

    @staticmethod
    def _extract_terminal_metrics(info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        info = info or {}
        return {
            "transformer_pass": bool(info.get("model_success", False)),
            "playwright_pass": bool(info.get("browser_success", False)),
            "modsec_pass": bool(info.get("modsec_success", False)),
            "modsec_blocked": bool(info.get("modsec_blocked", False)),
            "modsec_blocked_by_status": bool(info.get("modsec_blocked_by_status", False)),
            "modsec_blocked_by_headers": bool(info.get("modsec_blocked_by_headers", False)),
            "modsec_blocked_by_body": bool(info.get("modsec_blocked_by_body", False)),
            "modsec_status_code": info.get("modsec_status_code"),
            "triggered_crs_rule_count": int(info.get("triggered_crs_rule_count", -1)),
            "triggered_crs_rule_ids": list(info.get("triggered_crs_rule_ids", [])),
            "modsec_triggered_rules": list(info.get("modsec_triggered_rules", [])),
            "modsec_signal_count": int(info.get("modsec_signal_count", -1)),
            "modsec_block_reason": info.get("modsec_block_reason"),
            "playwright_error": info.get("playwright_error"),
            "modsec_error": info.get("modsec_error"),
        }

    def train_one_episode(self, env, episode_idx: int, max_steps: Optional[int] = None, render: bool = False) -> Dict[str, Any]:
        reset_out = env.reset()
        if isinstance(reset_out, tuple) and len(reset_out) == 2:
            state, info = reset_out
        else:
            state, info = reset_out, {}

        total_reward = 0.0
        steps = 0
        success = False
        mutated_success = False
        final_prob = info.get("prob", None)
        terminal_metrics = self._extract_terminal_metrics(info if isinstance(info, dict) else None)
        valid_start = bool(info.get("initial_payload_failed", not self._is_success(info, env))) if isinstance(info, dict) else True
        max_steps = max_steps or getattr(env, "max_steps", 50)

        initial_success = self._is_success(info, env) if isinstance(info, dict) else False
        if initial_success:
            total_reward += 10.0
            success = True
            if hasattr(env, "on_initial_success"):
                try:
                    env.on_initial_success()
                except Exception:
                    pass
            self.decay_epsilon(episode_idx)
            return {
                "total_reward": float(total_reward),
                "steps": int(steps),
                "success": bool(success),
                "initial_success": True,
                "mutated_success": False,
                "goal_success": False,
                "valid_start": bool(valid_start),
                "final_prob": (float(final_prob) if final_prob is not None else None),
                **terminal_metrics,
                "epsilon": float(self.epsilon),
            }

        for _ in range(max_steps):
            steps += 1
            action = self.act(state, eval_mode=False)
            result = env.step(action)

            if len(result) == 5:
                next_state, reward, terminated, truncated, info = result
            elif len(result) == 4:
                next_state, reward, done, info = result
                terminated, truncated = done, False
            else:
                raise RuntimeError(f"env.step returned unexpected length: {len(result)}")

            total_reward += float(reward)
            step_success = self._is_success(info, env) if isinstance(info, dict) else False
            if isinstance(info, dict):
                final_prob = info.get("prob", final_prob)
                terminal_metrics = self._extract_terminal_metrics(info)

            done_flag = terminated or truncated
            self.remember(state, action, reward, next_state, done_flag or step_success)
            self.train_step()
            state = next_state

            if step_success:
                success = True
                mutated_success = True
                break
            if done_flag:
                break

        self.decay_epsilon(episode_idx)
        return {
            "total_reward": float(total_reward),
            "steps": int(steps),
            "success": bool(success),
            "initial_success": False,
            "mutated_success": bool(mutated_success),
            "goal_success": bool(valid_start and mutated_success and steps >= 1),
            "valid_start": bool(valid_start),
            "final_prob": (float(final_prob) if final_prob is not None else None),
            **terminal_metrics,
            "epsilon": float(self.epsilon),
        }

    def evaluate(self, env, n_episodes: int = 20, max_steps: Optional[int] = None) -> Dict[str, Any]:
        rewards, steps_list, finals, success_cnt = [], [], [], 0
        initial_success_cnt, mutated_success_cnt = 0, 0
        valid_start_cnt, goal_success_cnt = 0, 0

        for _ in range(n_episodes):
            reset_out = env.reset()
            if isinstance(reset_out, tuple) and len(reset_out) == 2:
                state, info = reset_out
            else:
                state, info = reset_out, {}

            ep_reward = 0.0
            ep_steps = 0
            ep_success = False
            ep_final_prob = info.get("prob", None)
            valid_start = bool(info.get("initial_payload_failed", not self._is_success(info, env))) if isinstance(info, dict) else True
            if valid_start:
                valid_start_cnt += 1

            initial_success = self._is_success(info, env) if isinstance(info, dict) else False
            if initial_success:
                ep_reward += 10.0
                success_cnt += 1
                initial_success_cnt += 1
                if hasattr(env, "on_initial_success"):
                    try:
                        env.on_initial_success()
                    except Exception:
                        pass
                rewards.append(ep_reward)
                steps_list.append(ep_steps)
                if ep_final_prob is not None:
                    try:
                        finals.append(float(ep_final_prob))
                    except Exception:
                        pass
                continue

            use_max_steps = max_steps or getattr(env, "max_steps", 50)
            for _ in range(use_max_steps):
                ep_steps += 1
                action = self.act(state, eval_mode=True)
                result = env.step(action)

                if len(result) == 5:
                    next_state, reward, terminated, truncated, info = result
                elif len(result) == 4:
                    next_state, reward, done, info = result
                    terminated, truncated = done, False
                else:
                    raise RuntimeError(f"env.step returned unexpected length: {len(result)}")

                ep_reward += float(reward)
                state = next_state

                step_success = self._is_success(info, env) if isinstance(info, dict) else False
                if isinstance(info, dict):
                    ep_final_prob = info.get("prob", ep_final_prob)

                if step_success:
                    ep_success = True
                    mutated_success_cnt += 1
                    if valid_start and ep_steps >= 1:
                        goal_success_cnt += 1
                    break
                if terminated or truncated:
                    break

            rewards.append(ep_reward)
            steps_list.append(ep_steps)
            if ep_success:
                success_cnt += 1
            if ep_final_prob is not None:
                try:
                    finals.append(float(ep_final_prob))
                except Exception:
                    pass

        return {
            "success_rate": success_cnt / max(1, n_episodes),
            "initial_success_rate": initial_success_cnt / max(1, n_episodes),
            "mutated_success_rate": mutated_success_cnt / max(1, n_episodes),
            "valid_start_rate": valid_start_cnt / max(1, n_episodes),
            "goal_success_rate": goal_success_cnt / max(1, valid_start_cnt),
            "goal_success_count": int(goal_success_cnt),
            "valid_start_count": int(valid_start_cnt),
            "avg_reward": float(np.mean(rewards)) if rewards else 0.0,
            "avg_steps": float(np.mean(steps_list)) if steps_list else 0.0,
            "avg_final_prob": float(np.mean(finals)) if finals else None,
            "n_episodes": int(n_episodes),
        }


if __name__ == "__main__":
    print("ddqn_agent.py loaded. Instantiate DDQNAgent in your training script.")
