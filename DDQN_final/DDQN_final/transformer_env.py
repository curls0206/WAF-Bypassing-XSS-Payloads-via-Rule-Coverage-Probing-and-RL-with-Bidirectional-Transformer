from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import difflib
import re
from urllib.parse import quote, urlencode, urljoin, urlparse

import numpy as np

from mutation_ops import N_ACTIONS, REGISTRY as MUT_REGISTRY
from transformer_keras import XSSDetector
import logger as base_logger


@dataclass
class EnvHyper:
    max_steps_per_episode: int = 10
    html_url: str = "http://127.0.0.1:8081/vulnerabilities/xss_r/"

    # Reward shaping
    R_success: float = 10.0
    R_step_penalty: float = -0.1
    R_syntax_fail: float = -5.0
    w_delta: float = 1.0
    w_delta_neg: float = 0.3
    w_margin: float = 0.5
    w_len: float = -0.001
    w_lev: float = 0.2
    R_no_change: float = -0.05
    tiny_change_eps: float = 1e-4
    w_browser_bonus: float = 0.5
    w_modsec_margin: float = 0.5
    R_modsec_blocked: float = -1.0
    R_modsec_error: float = -1.5
    R_modsec_status_403_406: float = -0.5
    w_modsec_rule_count: float = -0.2
    w_modsec_signal_count: float = -0.05

    # Success criterion
    prob_success_threshold: float = 0.1
    success_mode: str = "model_browser_modsec"  # model_only | model_and_browser | model_browser_modsec
    min_mutation_steps_for_success: int = 1
    require_initial_failure: bool = True
    reset_resample_attempts: int = 50

    # Detector config
    keras_model_path: str = "BestModel_Transformer.keras"
    max_len: int = 600

    # Browser verification
    enable_browser_check: bool = True
    browser_timeout_s: float = 5.0
    browser_param_name: str = "name"
    dvwa_username: str = "admin"
    dvwa_password: str = "password"
    dvwa_security_level: str = "low"

    # ModSecurity verification
    enable_modsec_check: bool = True
    modsec_url: str = "http://localhost/vulnerabilities/xss_r/"
    modsec_param_name: str = "name"
    modsec_timeout_s: float = 10.0
    modsec_success_mode: str = "not_blocked"  # not_blocked | not_blocked_and_crs
    max_triggered_crs_rules: int = 2


class _LoggerAdapter:
    def __init__(self):
        self._payload_id: Optional[str] = None

    def start_payload_session(self, original_payload: str, meta: Optional[dict] = None):
        from datetime import datetime

        self._payload_id = f"seed_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        base_logger.start_payload_session(self._payload_id, original_payload, meta or {})

    def record_payload_step(
        self,
        step: int,
        action: int,
        prob: float,
        delta_prob: float,
        reward: float,
        success: bool,
        payload: str,
        lev_sim: float = 1.0,
        action_name: Optional[str] = None,
        diff: Optional[str] = None,
    ):
        if action_name is None:
            action_name = f"action_{action}"
        base_logger.record_payload_step(
            step=step,
            action_name=action_name,
            new_payload=payload,
            prob=float(prob),
            lev_sim=float(lev_sim),
            reward=float(reward),
            success=bool(success),
            delta_prob=float(delta_prob),
            diff=diff,
        )

    def end_payload_session(self, success: bool, final_payload: str = "", final_prob: Optional[float] = None):
        extra = {"final_payload": final_payload}
        if final_prob is not None:
            extra["final_prob"] = float(final_prob)
        if self._payload_id is None:
            self._payload_id = "anon"
        base_logger.end_payload_session(self._payload_id, bool(success), extra_info=extra)
        self._payload_id = None


class PlaywrightController:
    def __init__(
        self,
        html_url: str,
        headless: bool = True,
        timeout_s: float = 5.0,
        enabled: bool = True,
        param_name: str = "input",
        dvwa_username: str = "admin",
        dvwa_password: str = "password",
        dvwa_security_level: str = "low",
    ):
        self.html_url = html_url
        self.headless = headless
        self.timeout_s = timeout_s
        self.enabled = enabled
        self.param_name = param_name
        self.dvwa_username = dvwa_username
        self.dvwa_password = dvwa_password
        self.dvwa_security_level = dvwa_security_level

        self._ready = False
        self._ready_error: Optional[str] = None
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._dialog_count = 0
        self._console_count = 0
        self._dvwa_ready = False

        if not self.enabled:
            self._ready_error = "browser_check_disabled"
            return

        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            self._ready = True
        except Exception as e:
            self._ready_error = f"{type(e).__name__}: {e}"

    def _is_dvwa_target(self) -> bool:
        url_lower = self.html_url.lower()
        return "dvwa" in url_lower or "/vulnerabilities/xss_r/" in url_lower

    def _build_target_url(self, payload: str) -> str:
        if self._is_dvwa_target():
            q = urlencode({self.param_name: payload, "Submit": "Submit"})
            join_base = self.html_url if self.html_url.endswith("/") else self.html_url + "/"
            return f"{join_base}?{q}"
        return f"{self.html_url}?{self.param_name}={payload}"

    @staticmethod
    def _extract_hidden_token(page, name: str = "user_token") -> Optional[str]:
        try:
            locator = page.locator(f'input[name="{name}"]')
            if locator.count() > 0:
                return locator.first.get_attribute("value")
        except Exception:
            return None
        return None

    def _dvwa_login(self, page, wait_ms: int) -> None:
        parsed = urlparse(self.html_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        login_url = urljoin(base_url, "login.php")
        page.goto(login_url, wait_until="load", timeout=wait_ms)

        if "login.php" not in page.url.lower():
            return

        token = self._extract_hidden_token(page)
        page.fill('input[name="username"]', self.dvwa_username)
        page.fill('input[name="password"]', self.dvwa_password)
        if token is not None:
            try:
                page.fill('input[name="user_token"]', token)
            except Exception:
                pass
        page.click('input[name="Login"], button[name="Login"], input[type="submit"], button[type="submit"]')
        page.wait_for_load_state("load", timeout=wait_ms)

        security_url = urljoin(base_url, "security.php")
        page.goto(security_url, wait_until="load", timeout=wait_ms)
        try:
            if page.locator('select[name="security"]').count() > 0:
                page.select_option('select[name="security"]', self.dvwa_security_level)
                token = self._extract_hidden_token(page)
                if token is not None:
                    try:
                        page.fill('input[name="user_token"]', token)
                    except Exception:
                        pass
                page.click('input[name="seclev_submit"], button[name="seclev_submit"], input[type="submit"], button[type="submit"]')
                page.wait_for_load_state("load", timeout=wait_ms)
        except Exception:
            pass

    def _on_dialog(self, dialog) -> None:
        self._dialog_count += 1
        try:
            dialog.dismiss()
        except Exception:
            pass

    def _on_console(self, _msg) -> None:
        self._console_count += 1

    def _reset_event_counters(self) -> None:
        self._dialog_count = 0
        self._console_count = 0

    def _reset_session(self) -> None:
        try:
            if self._page is not None:
                self._page.close()
        except Exception:
            pass
        try:
            if self._context is not None:
                self._context.close()
        except Exception:
            pass
        try:
            if self._browser is not None:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception:
            pass
        self._page = None
        self._context = None
        self._browser = None
        self._pw = None
        self._dvwa_ready = False
        self._reset_event_counters()

    def _ensure_session(self, wait_ms: int) -> None:
        if self._page is None:
            from playwright.sync_api import sync_playwright

            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(headless=self.headless)
            self._context = self._browser.new_context()
            self._page = self._context.new_page()
            self._page.on("dialog", self._on_dialog)
            self._page.on("console", self._on_console)
            self._dvwa_ready = False

        if self._is_dvwa_target() and not self._dvwa_ready:
            self._dvwa_login(self._page, wait_ms)
            self._dvwa_ready = True

    def test_payload(self, payload: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        if not self._ready:
            return {
                "success": False,
                "dialog_count": 0,
                "console_count": 0,
                "has_script": False,
                "error": self._ready_error,
            }

        wait_ms = int(1000 * (timeout if timeout is not None else self.timeout_s))
        target_url = self._build_target_url(payload)

        for attempt in range(2):
            try:
                self._ensure_session(wait_ms)
                self._reset_event_counters()
                self._page.goto(target_url, wait_until="load", timeout=wait_ms)
                self._page.wait_for_timeout(300)
                selector = '#inner-html-target' if not self._is_dvwa_target() else '#main_body'
                has_script = self._page.evaluate(
                    """(selector) => {
                        const root = document.querySelector(selector);
                        if (!root) return false;
                        return !!root.querySelector('script');
                    }""",
                    selector,
                )
                return {
                    "success": (self._dialog_count > 0) or (self._console_count > 0) or bool(has_script),
                    "dialog_count": int(self._dialog_count),
                    "console_count": int(self._console_count),
                    "has_script": bool(has_script),
                    "error": None,
                }
            except Exception as e:
                self._reset_session()
                if attempt == 1:
                    return {
                        "success": False,
                        "dialog_count": 0,
                        "console_count": 0,
                        "has_script": False,
                        "error": f"{type(e).__name__}: {e}",
                    }

    def close(self):
        self._reset_session()
        return


class ModSecurityController:
    def __init__(
        self,
        modsec_url: str,
        param_name: str = "input",
        timeout_s: float = 10.0,
        enabled: bool = True,
        max_triggered_crs_rules: int = 2,
        success_mode: str = "not_blocked",
        dvwa_username: str = "admin",
        dvwa_password: str = "password",
        dvwa_security_level: str = "low",
    ):
        self.modsec_url = modsec_url
        self.param_name = param_name
        self.timeout_s = timeout_s
        self.enabled = enabled
        self.max_triggered_crs_rules = max_triggered_crs_rules
        self.success_mode = success_mode
        self.dvwa_username = dvwa_username
        self.dvwa_password = dvwa_password
        self.dvwa_security_level = dvwa_security_level

        self._ready = False
        self._ready_error: Optional[str] = None
        self._session = None
        self._dvwa_ready = False

        if not self.enabled:
            self._ready_error = "modsec_check_disabled"
            return

        try:
            import requests  # noqa: F401
            self._ready = True
        except Exception as e:
            self._ready_error = f"{type(e).__name__}: {e}"

    def _is_dvwa_target(self) -> bool:
        return "dvwa" in self.modsec_url.lower() or "/vulnerabilities/xss_r/" in self.modsec_url.lower()

    def _build_target_url(self, payload: str) -> str:
        if self._is_dvwa_target():
            encoded = urlencode({self.param_name: payload, "Submit": "Submit"})
            join_base = self.modsec_url if self.modsec_url.endswith("/") else self.modsec_url + "/"
            return f"{join_base}?{encoded}"
        return f"{self.modsec_url}?{self.param_name}={quote(payload)}"

    @staticmethod
    def _extract_hidden_token(text: str, name: str = "user_token") -> Optional[str]:
        match = re.search(
            rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]+value=["\']([^"\']+)["\']',
            text,
            re.IGNORECASE,
        )
        return match.group(1) if match else None

    def _ensure_session(self):
        if self._session is None:
            import requests

            self._session = requests.Session()
            self._session.headers.update({"User-Agent": "DDQN-ModSec-Session/1.0"})
            self._dvwa_ready = False

        if self._is_dvwa_target() and not self._dvwa_ready:
            self._dvwa_login()
            self._dvwa_ready = True

    def _dvwa_login(self) -> None:
        parsed = urlparse(self.modsec_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        login_url = urljoin(base_url, "login.php")
        response = self._session.get(login_url, timeout=self.timeout_s, allow_redirects=True)
        token = self._extract_hidden_token(response.text)
        payload = {
            "username": self.dvwa_username,
            "password": self.dvwa_password,
            "Login": "Login",
        }
        if token:
            payload["user_token"] = token
        self._session.post(login_url, data=payload, timeout=self.timeout_s, allow_redirects=True)

        security_url = urljoin(base_url, "security.php")
        response = self._session.get(security_url, timeout=self.timeout_s, allow_redirects=True)
        token = self._extract_hidden_token(response.text)
        payload = {
            "security": self.dvwa_security_level,
            "seclev_submit": "Submit",
        }
        if token:
            payload["user_token"] = token
        self._session.post(security_url, data=payload, timeout=self.timeout_s, allow_redirects=True)

    def test_payload(self, payload: str) -> Dict[str, Any]:
        if not self._ready:
            return {
                "success": False,
                "blocked": False,
                "blocked_by_status": False,
                "blocked_by_headers": False,
                "blocked_by_body": False,
                "triggered_rules": [],
                "triggered_crs_rule_ids": [],
                "triggered_crs_rule_count": 999,
                "modsec_signal_count": 999,
                "block_reason": self._ready_error,
                "status_code": None,
                "error": self._ready_error,
            }

        try:
            self._ensure_session()
            test_url = self._build_target_url(payload)
            response = self._session.get(test_url, timeout=self.timeout_s, allow_redirects=False)

            blocked_by_status = response.status_code in [403, 406]
            blocked = blocked_by_status
            triggered_rules: List[str] = []
            blocked_by_headers = False
            blocked_by_body = False

            for header in ["X-Mod-Security-Message", "X-WAF-Status", "X-WAF-Blocked"]:
                if header in response.headers:
                    blocked = True
                    blocked_by_headers = True
                    triggered_rules.append(f"Header: {header}={response.headers[header]}")

            body_lower = response.text.lower()
            for indicator in ["modsecurity", "waf blocked", "access denied", "forbidden", "406 not acceptable"]:
                if indicator in body_lower:
                    blocked = True
                    blocked_by_body = True
                    triggered_rules.append(f"Body: {indicator}")

            rule_matches = re.findall(r'id[:\s]*"?(\d+)"?', response.text, re.IGNORECASE)
            for rid in rule_matches:
                triggered_rules.append(f"Rule ID: {rid}")

            crs_rule_ids = sorted(
                {
                    rid
                    for rid in rule_matches
                    if rid.isdigit() and 900000 <= int(rid) <= 999999
                }
            )
            crs_rule_count = len(crs_rule_ids)
            modsec_signal_count = len(triggered_rules)
            block_reason = None
            if blocked_by_status:
                block_reason = f"http_{response.status_code}"
            elif blocked_by_headers:
                block_reason = "header_indicator"
            elif blocked_by_body:
                block_reason = "body_indicator"
            success = not blocked
            if self.success_mode == "not_blocked_and_crs":
                success = success and (crs_rule_count <= self.max_triggered_crs_rules)

            return {
                "success": bool(success),
                "success_mode": self.success_mode,
                "blocked": bool(blocked),
                "blocked_by_status": bool(blocked_by_status),
                "blocked_by_headers": bool(blocked_by_headers),
                "blocked_by_body": bool(blocked_by_body),
                "triggered_rules": triggered_rules,
                "triggered_crs_rule_ids": crs_rule_ids,
                "triggered_crs_rule_count": int(crs_rule_count),
                "modsec_signal_count": int(modsec_signal_count),
                "block_reason": block_reason,
                "status_code": int(response.status_code),
                "error": None,
            }
        except Exception as e:
            return {
                "success": False,
                "blocked": False,
                "blocked_by_status": False,
                "blocked_by_headers": False,
                "blocked_by_body": False,
                "triggered_rules": [],
                "triggered_crs_rule_ids": [],
                "triggered_crs_rule_count": 999,
                "modsec_signal_count": 999,
                "block_reason": "request_error",
                "status_code": None,
                "error": f"{type(e).__name__}: {e}",
            }

    def close(self):
        try:
            if self._session is not None:
                self._session.close()
        except Exception:
            pass
        self._session = None
        self._dvwa_ready = False


class TransformerEnv:
    def __init__(
        self,
        env_hyper: Optional[EnvHyper] = None,
        detector: Optional[XSSDetector] = None,
        playwright: Optional[PlaywrightController] = None,
        seed_payloads: Optional[List[str]] = None,
    ):
        self.cfg = env_hyper or EnvHyper()
        self.logger = _LoggerAdapter()
        self.play = playwright or PlaywrightController(
            self.cfg.html_url,
            headless=True,
            timeout_s=self.cfg.browser_timeout_s,
            enabled=self.cfg.enable_browser_check,
            param_name=self.cfg.browser_param_name,
            dvwa_username=self.cfg.dvwa_username,
            dvwa_password=self.cfg.dvwa_password,
            dvwa_security_level=self.cfg.dvwa_security_level,
        )
        self.modsec = ModSecurityController(
            modsec_url=self.cfg.modsec_url,
            param_name=self.cfg.modsec_param_name,
            timeout_s=self.cfg.modsec_timeout_s,
            enabled=self.cfg.enable_modsec_check,
            max_triggered_crs_rules=self.cfg.max_triggered_crs_rules,
            success_mode=self.cfg.modsec_success_mode,
            dvwa_username=self.cfg.dvwa_username,
            dvwa_password=self.cfg.dvwa_password,
            dvwa_security_level=self.cfg.dvwa_security_level,
        )
        self.detector = detector or XSSDetector(model_path=self.cfg.keras_model_path, max_len=self.cfg.max_len)

        self.action_space_n = N_ACTIONS
        self._rng = np.random.default_rng(seed=2025)
        self._seed_payloads = seed_payloads or [
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "<iframe srcdoc='<script>console.log(1)</script>'>",
            "<details open ontoggle=alert(1)>",
        ]

        self.max_steps = self.cfg.max_steps_per_episode
        self.steps = 0
        self.orig_payload: str = ""
        self.current_payload: str = ""
        self.prev_prob: float = 1.0
        self.initial_prob: float = 1.0
        self.initial_payload_failed: bool = True
        self.last_action: int = -1
        self._session_closed: bool = True

        self.obs_dim = 3 + self.action_space_n

    def reset(self, payload: Optional[str] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        self.orig_payload = self._pick_initial_payload(payload)
        self.current_payload = self.orig_payload
        self.steps = 0
        self.last_action = -1
        self._session_closed = False

        self.logger.start_payload_session(self.orig_payload)

        self.prev_prob = self._get_prob(self.current_payload)
        self.initial_prob = self.prev_prob
        model_success = bool(self.prev_prob <= self.cfg.prob_success_threshold)
        browser_success = False
        modsec_success = False
        success = self._is_success(
            model_success=model_success,
            browser_success=browser_success,
            modsec_success=modsec_success,
        )
        self.initial_payload_failed = not model_success

        info = {
            "prob": float(self.prev_prob),
            "success": success,
            "model_success": model_success,
            "browser_success": browser_success,
            "modsec_success": modsec_success,
            "modsec_blocked": False,
            "modsec_blocked_by_status": False,
            "modsec_blocked_by_headers": False,
            "modsec_blocked_by_body": False,
            "modsec_status_code": None,
            "triggered_crs_rule_count": 999,
            "triggered_crs_rule_ids": [],
            "modsec_triggered_rules": [],
            "modsec_signal_count": 999,
            "modsec_block_reason": None,
            "playwright_error": None,
            "modsec_error": None,
            "payload": self.current_payload,
            "steps": 0,
            "delta_prob": 0.0,
            "lev_sim": 1.0,
            "initial_payload_failed": bool(self.initial_payload_failed),
        }
        state = self._build_state(prob=self.prev_prob)
        return state, info

    def on_initial_success(self):
        if not self._session_closed:
            self.logger.end_payload_session(
                success=True,
                final_payload=self.current_payload,
                final_prob=float(self.prev_prob),
            )
            self._session_closed = True

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        self.steps += 1

        entry = MUT_REGISTRY[action]
        if isinstance(entry, tuple) and len(entry) == 3:
            action_name, _, mutate_fn = entry
        else:
            mutate_fn = entry if callable(entry) else entry[-1]
            action_name = getattr(mutate_fn, "__name__", f"action_{action}")

        old_payload = self.current_payload
        new_payload = mutate_fn(old_payload, self._rng)

        prob = self._get_prob(new_payload)
        delta_prob = float(self.prev_prob - prob)
        lev_sim = self._levenshtein_similarity(old_payload, new_payload)

        browser_result = self.play.test_payload(new_payload)
        browser_success = bool(browser_result.get("success", False))

        modsec_result = self.modsec.test_payload(new_payload)
        modsec_success = bool(modsec_result.get("success", False))

        model_success = bool(prob <= self.cfg.prob_success_threshold)
        success = self._is_success(
            model_success=model_success,
            browser_success=browser_success,
            modsec_success=modsec_success,
        )

        reward = self._calc_reward(
            prev_prob=self.prev_prob,
            curr_prob=prob,
            success=success,
            old_payload=old_payload,
            new_payload=new_payload,
            lev_sim=lev_sim,
            steps=self.steps,
            browser_success=browser_success,
            modsec_success=modsec_success,
            modsec_blocked=bool(modsec_result.get("blocked", False)),
            modsec_status_code=modsec_result.get("status_code"),
            modsec_rule_count=int(modsec_result.get("triggered_crs_rule_count", 999)),
            modsec_signal_count=int(modsec_result.get("modsec_signal_count", 999)),
            modsec_error=modsec_result.get("error"),
        )

        done = success or (self.steps >= self.max_steps)
        info = {
            "prob": float(prob),
            "success": success,
            "model_success": model_success,
            "browser_success": browser_success,
            "modsec_success": modsec_success,
            "modsec_blocked": bool(modsec_result.get("blocked", False)),
            "modsec_blocked_by_status": bool(modsec_result.get("blocked_by_status", False)),
            "modsec_blocked_by_headers": bool(modsec_result.get("blocked_by_headers", False)),
            "modsec_blocked_by_body": bool(modsec_result.get("blocked_by_body", False)),
            "modsec_status_code": modsec_result.get("status_code"),
            "triggered_crs_rule_count": int(modsec_result.get("triggered_crs_rule_count", 999)),
            "triggered_crs_rule_ids": modsec_result.get("triggered_crs_rule_ids", []),
            "modsec_triggered_rules": modsec_result.get("triggered_rules", []),
            "modsec_signal_count": int(modsec_result.get("modsec_signal_count", 999)),
            "modsec_block_reason": modsec_result.get("block_reason"),
            "playwright_error": browser_result.get("error"),
            "modsec_error": modsec_result.get("error"),
            "payload": new_payload,
            "steps": int(self.steps),
            "delta_prob": delta_prob,
            "lev_sim": float(lev_sim),
            "initial_payload_failed": bool(self.initial_payload_failed),
        }

        diff_summary = self._summarize_payload_diff(old_payload, new_payload)
        self.logger.record_payload_step(
            step=self.steps,
            action=action,
            prob=float(prob),
            delta_prob=delta_prob,
            reward=float(reward),
            success=success,
            payload=new_payload,
            lev_sim=float(lev_sim),
            action_name=action_name,
            diff=diff_summary,
        )

        self.current_payload = new_payload
        self.prev_prob = prob
        self.last_action = action

        state = self._build_state(prob=prob)
        if done and not self._session_closed:
            self.logger.end_payload_session(success=success, final_payload=new_payload, final_prob=float(prob))
            self._session_closed = True

        return state, float(reward), done, info

    def close(self):
        try:
            self.play.close()
        except Exception:
            pass
        try:
            self.modsec.close()
        except Exception:
            pass

    def _get_prob(self, payload: str) -> float:
        if hasattr(self.detector, "predict_proba"):
            try:
                p = float(self.detector.predict_proba(payload))
                if np.isnan(p) or np.isinf(p):
                    return 1.0
                return float(max(0.0, min(1.0, p)))
            except Exception:
                pass

        try:
            cls = int(self.detector.is_xss(payload))
        except Exception:
            return 1.0
        return 0.9 if cls == 1 else 0.1

    def _build_state(self, prob: float) -> np.ndarray:
        len_norm = min(len(self.current_payload), 1024) / 1024.0
        step_ratio = self.steps / max(1, self.max_steps)

        last_onehot = np.zeros(self.action_space_n, dtype=np.float32)
        if 0 <= self.last_action < self.action_space_n:
            last_onehot[self.last_action] = 1.0

        return np.concatenate(
            [
                np.array([prob, len_norm, step_ratio], dtype=np.float32),
                last_onehot,
            ],
            axis=0,
        )

    def _pick_initial_payload(self, payload: Optional[str]) -> str:
        if payload is not None or not self.cfg.require_initial_failure:
            return payload if payload is not None else str(self._rng.choice(self._seed_payloads))

        candidate = str(self._rng.choice(self._seed_payloads))
        for _ in range(max(1, int(self.cfg.reset_resample_attempts))):
            prob = self._get_prob(candidate)
            if prob > self.cfg.prob_success_threshold:
                return candidate
            candidate = str(self._rng.choice(self._seed_payloads))
        return candidate

    def _is_success(self, model_success: bool, browser_success: bool, modsec_success: bool) -> bool:
        if self.steps < max(0, int(self.cfg.min_mutation_steps_for_success)):
            return False
        if self.cfg.success_mode == "model_browser_modsec":
            return bool(model_success and browser_success and modsec_success)
        if self.cfg.success_mode == "model_and_browser":
            return bool(model_success and browser_success)
        return bool(model_success)

    def _calc_reward(
        self,
        prev_prob: float,
        curr_prob: float,
        success: bool,
        old_payload: str,
        new_payload: str,
        lev_sim: float,
        steps: int,
        browser_success: bool,
        modsec_success: bool,
        modsec_blocked: bool,
        modsec_status_code: Optional[int],
        modsec_rule_count: int,
        modsec_signal_count: int,
        modsec_error: Optional[str],
    ) -> float:
        reward = 0.0
        if success:
            step_bonus = min(steps * 1.5, 7.5)
            reward += self.cfg.R_success + step_bonus

        delta_pos = max(prev_prob - curr_prob, 0.0)
        delta_neg = max(curr_prob - prev_prob, 0.0)
        reward += self.cfg.w_delta * delta_pos
        reward -= self.cfg.w_delta_neg * delta_neg
        reward += self.cfg.w_margin * max(self.cfg.prob_success_threshold - curr_prob, 0.0)

        reward += self.cfg.w_browser_bonus if browser_success else -self.cfg.w_browser_bonus
        if modsec_success:
            reward += self.cfg.w_modsec_margin
        else:
            reward += self.cfg.R_modsec_blocked if modsec_blocked else 0.0
            reward += self.cfg.R_modsec_error if modsec_error else 0.0
            if modsec_status_code in [403, 406]:
                reward += self.cfg.R_modsec_status_403_406
            reward += self.cfg.w_modsec_rule_count * min(float(modsec_rule_count), 5.0)
            reward += self.cfg.w_modsec_signal_count * min(float(modsec_signal_count), 10.0)

        reward += self.cfg.w_len * float(len(new_payload))
        reward += self.cfg.w_lev * float(lev_sim)
        reward += self.cfg.R_step_penalty

        if old_payload == new_payload or abs(curr_prob - prev_prob) < self.cfg.tiny_change_eps:
            reward += self.cfg.R_no_change
        return reward

    def _levenshtein_similarity(self, old: str, new: str) -> float:
        return float(difflib.SequenceMatcher(a=old, b=new).ratio())

    def _summarize_payload_diff(self, old: str, new: str) -> str:
        diff = difflib.ndiff(old.split(), new.split())
        changes = [x for x in diff if x.startswith("+ ") or x.startswith("- ")]
        if not changes:
            return "No change"
        if len(changes) > 8:
            changes = changes[:8] + ["..."]
        return " | ".join(changes)
