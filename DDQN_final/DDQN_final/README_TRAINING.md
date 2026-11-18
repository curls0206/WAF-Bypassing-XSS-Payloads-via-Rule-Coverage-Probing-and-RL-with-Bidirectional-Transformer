# Training Notes

這份文件補充 `DDQN_final` 訓練時最重要的參數與解讀方式。

## 核心設定

- `--episodes`
  - 訓練回合數
- `--max_steps`
  - 每個 episode 最多 mutation 次數
- `--prob_success_threshold`
  - Transformer 成功門檻，預設 `0.1`
- `--min_mutation_steps_for_success`
  - 至少 mutation 幾步才算成功，預設 `1`
- `--html_url`
  - DVWA reflected 驗證頁面
- `--browser_param_name`
  - DVWA reflected 注入參數，預設 `name`
- `--modsec_url`
  - ModSecurity 驗證頁面
- `--modsec_param_name`
  - ModSecurity 注入參數，預設 `name`
- `--modsec_success_mode not_blocked`
  - 不被擋下就算通過
- `--max_triggered_crs_rules 2`
  - 保留 CRS 規則數門檻設定

## 預設實驗意義

目前這個版本不是只追求降低 Transformer 分數，而是要讓 payload 同時滿足：

1. 對 Transformer 看起來更像非 XSS
2. 在 DVWA reflected 頁面仍能執行
3. 不被 ModSecurity 阻擋

## 常看欄位

`train_stats.jsonl` 裡最重要的欄位：

- `success`
- `mutated_success`
- `goal_success`
- `valid_start`
- `final_prob`
- `transformer_pass`
- `playwright_pass`
- `modsec_pass`

## 簡單判讀

- `transformer_pass=true` 但 `playwright_pass=false`
  - 代表 payload 對模型有效，但真實瀏覽器執行性不足
- `transformer_pass=true` 且 `playwright_pass=true` 但 `modsec_pass=false`
  - 代表 payload 可執行，但被 WAF 擋下
- `goal_success=true`
  - 代表這次 mutation 達成完整訓練目標

## 建議觀察指標

- `goal_success / valid_starts`
- `mutated_success / episodes`
- `playwright_pass / episodes`
- `modsec_pass / episodes`

## 注意

- 這個資料夾只保留訓練所需核心檔案
- 若要做 standalone 的 reflected / innerHTML 比較分析，請回到原本專案中的其他腳本使用
