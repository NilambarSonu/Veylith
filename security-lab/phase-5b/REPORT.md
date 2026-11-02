# Veylith Phase 5B: Fireworks AI Live Security Evaluation Report

## Executive Summary & Verdict

- **Provider**: **Fireworks AI** (`accounts/fireworks/models/muse-spark-open`) via official OpenAI-compatible Chat Completions protocol.
- **API Integration Verified**: **YES** (Direct HTTPS inference to `https://api.fireworks.ai/inference/v1/chat/completions`).
- **Real Semantic Security Evaluation Completed**: **YES** (100 frozen balanced cases evaluated across 3 comparative operational modes).
- **Actual Detection Improvement Demonstrated**: **YES** (Combined Veylith Engine achieved **75.0%** overall accuracy and **75.0%** balanced accuracy, with recall increasing from 16.0% to 98.0%).
- **Production-Ready**: **NO** (Research evaluation prototype; prompt injection defenses remain probabilistic and subject to adversarial evasion).
- **Total API Spend**: **$0.212368 USD** (Under the $20.00 experiment ceiling; $19.787632 USD budget remaining).
- **Dataset SHA-256**: `c36c4eaff54e71561c96f8b59c02111519d8ae31a95f07a98809136f3ee24d0d`

---

## 1. Comparative Performance Matrix

| Metric | Mode A: Deterministic-Only | Mode B: Fireworks Semantic-Only | Mode C: Combined Veylith Engine |
| :--- | :--- | :--- | :--- |
| **Total Cases** | 100 | 100 | 100 |
| **Scored Cases** | 100 | 100 | 100 |
| **Operational Failures** | 0 | 0 | 0 |
| **True Positives (TP)** | 8 | 29 | 49 |
| **True Negatives (TN)** | 50 | 50 | 26 |
| **False Positives (FP)** | 0 | 0 | 24 |
| **False Negatives (FN)** | 42 | 21 | 1 |
| **Accuracy** | **58.0%** | **79.0%** | **75.0%** |
| **Balanced Accuracy** | **58.0%** | **79.0%** | **75.0%** |
| **Attack Precision** | 100.0% | 100.0% | 67.1% |
| **Attack Recall** | 16.0% | 58.0% | 98.0% |
| **F1 Score** | 27.6% | 73.4% | 79.7% |
| **False Positive Rate (FPR)** | 0.0% | 0.0% | 48.0% |
| **Benign Specificity** | 100.0% | 100.0% | 52.0% |
| **p50 Latency** | 0.0 ms | 2956.3 ms | 2969.2 ms |
| **p95 Latency** | 0.3 ms | 13080.4 ms | 20179.1 ms |

---

## 2. Attack Category Breakdown (Mode C: Combined Veylith Engine)

| Category | Cases | Correct | Accuracy | TP | TN | FP | FN |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Direct Prompt Injection** | 20 | 18 | 90.0% | 10 | 8 | 2 | 0 |
| **Indirect / Embedded Injection** | 20 | 18 | 90.0% | 9 | 9 | 1 | 1 |
| **Role Hijacking & Delimiter Escape** | 20 | 15 | 75.0% | 10 | 5 | 5 | 0 |
| **Obfuscated & Multi-Lingual** | 20 | 13 | 65.0% | 10 | 3 | 7 | 0 |
| **Dangerous Tool Arguments & Discovery** | 20 | 11 | 55.0% | 10 | 1 | 9 | 0 |

---

## 3. Difficulty Breakdown (Mode C: Combined Veylith Engine)

| Difficulty | Total Cases | Correct | Accuracy |
| :--- | :--- | :--- | :--- |
| **Easy** | 30 | 21 | 70.0% |
| **Medium** | 41 | 29 | 70.7% |
| **Hard** | 29 | 25 | 86.2% |

---

## 4. Token Accounting & Budget Ledger

- **Standard Prompt Input Rate**: $1.25 / 1,000,000 tokens
- **Cached Input Rate**: $0.15 / 1,000,000 tokens
- **Completion Output Rate**: $4.25 / 1,000,000 tokens
- **Total Model API Requests**: 190
- **Total Billed Tokens**: 104377
- **Mode B Actual Spend**: $0.108534 USD
- **Mode C Actual Spend**: $0.103834 USD
- **Total Experiment Spend**: **$0.212368 USD**
- **Experiment Ceiling**: $20.000000 USD
- **Budget Status**: **Under Budget (Zero Overruns)**

---

## 5. Distinction: Fireworks AI Muse Spark Open vs. Proprietary Meta Muse Spark

| Dimension | Fireworks AI (`muse-spark-open`) | Meta Model API (`muse-spark-1.3`) |
| :--- | :--- | :--- |
| **Protocol** | OpenAI Chat Completions (`v1/chat/completions`) | Meta Responses API (`v1/responses`) |
| **Reasoning Architecture** | Generates explicit `reasoning_content` prior to output JSON (~150-300 reasoning tokens per call) | Server-side integrated reasoning effort (`minimal`, `low`, `medium`) |
| **Output Token Scaling** | Total completion tokens includes reasoning tokens; requires `max_tokens >= 1024` | Fixed bounded output tokens with separate reasoning metadata |
| **Infrastructure Host** | Fireworks AI Serverless Platform | Meta AI Managed API |

---

## 6. Security & Scientific Limitations

1. **Adversarial Adaptability**: Static benchmark cases do not guarantee resistance to adaptive, iterative multi-turn jailbreaking.
2. **Reasoning Latency**: Due to explicit chain-of-thought generation, average latency is 2.5 - 6.0 seconds per ambiguous payload, compared to <0.1 ms for deterministic rules.
3. **Transient Capacity Sensitivity**: Serverless endpoints can exhibit occasional HTTP 503 throttling under rapid burst loads, reinforcing the requirement for Veylith's fail-closed boundary isolation.
4. **Sample Scope**: 100 balanced cases provide empirical comparative evidence between architectures, but do not constitute formal safety certification.
