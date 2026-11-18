# DDQN_final

這個資料夾是可直接執行的最終訓練版本，目標是訓練一個 DDQN 代理，對 XSS payload 做 mutation，並以三段條件判定成功：

1. `Transformer` 分數通過門檻
2. `DVWA reflected XSS` 在瀏覽器中仍可執行
3. `ModSecurity` 不阻擋請求

## 必要前提

- DVWA reflected 頁面可用：
  - `http://127.0.0.1:8081/vulnerabilities/xss_r/`
- ModSecurity 測試端點可用：
  - `http://localhost/vulnerabilities/xss_r/`
- `BestModel_Transformer.keras` 已在此資料夾中
- `payloads.txt` 已在此資料夾中

## 主要檔案

- `transformer_ddqn.py`：訓練入口
- `transformer_env.py`：環境與成功條件
- `ddqn_agent.py`：DDQN agent
- `transformer_keras.py`：Transformer 偵測器
- `mutation_ops.py`：payload mutation 規則
- `logger.py`：訓練與 payload session 紀錄
- `payloads.txt`：seed payload 集合
- `BestModel_Transformer.keras`：Transformer 模型

## 訓練指令

在 `DDQN_final` 目錄下執行：

```powershell
python transformer_ddqn.py `
  --episodes 100 `
  --max_steps 10 `
  --prob_success_threshold 0.1 `
  --min_mutation_steps_for_success 1 `
  --html_url http://127.0.0.1:8081/vulnerabilities/xss_r/ `
  --browser_param_name name `
  --modsec_url http://localhost/vulnerabilities/xss_r/ `
  --modsec_param_name name `
  --modsec_success_mode not_blocked `
  --max_triggered_crs_rules 2 `
  --save_path trained_ddqn.pth
```

## 成功條件

一次 episode 只有在以下條件全部成立時才算真正成功：

- 初始 payload 沒有先通過 Transformer
- 至少做了 1 次 mutation
- 最終 payload 的 Transformer 分數 `<= 0.1`
- 最終 payload 通過 DVWA reflected 的 Playwright 驗證
- 最終 payload 通過 ModSecurity 驗證

## 輸出檔案

訓練完成後，常用輸出有：

- `trained_ddqn.pth`：訓練完成的 DDQN 權重
- `runs/transformer_ddqn/train_stats.jsonl`：每個 episode 的結果
- `res/logs_payload/payload_sessions.jsonl`：每條 payload mutation 過程
- `success_payloads_transformer.txt`：成功 payload

## 看結果時先看什麼

- `goal_success`
- `mutated_success`
- `valid_start`
- `final_prob`
- `playwright_pass`
- `modsec_pass`

其中最重要的是：

- `goal_success / valid_starts`

## 補充

更細的參數說明放在 [README_TRAINING.md](/c:/Users/user/Desktop/DDQN_TO_TRANSFORMER/DDQN_transformer_ver1/DDQN_final/README_TRAINING.md)。
