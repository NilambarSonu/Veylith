# Manual real model results (Meta Model API)

1 synthetic cases; 1 attempted paid calls. Pipeline metrics (cases routed around inference remain visible):

```json
{
  "samples": 1,
  "classificationSamples": 1,
  "tp": 0,
  "tn": 1,
  "fp": 0,
  "fn": 0,
  "precision": null,
  "recall": null,
  "falsePositiveRate": 0,
  "falseNegativeRate": null,
  "accuracy": 1,
  "enforcementSuccesses": 1,
  "enforcementSuccessRate": 1,
  "unsupported": 0,
  "forwardingViolations": 0,
  "isolationFailures": 0,
  "p50Ms": 3741.5594579999997,
  "p95Ms": 3741.5594579999997,
  "p99Ms": 3741.5594579999997
}
```

Estimated known-usage cost: $0.00106975. Conservative reserved cost: $0.00449475. Provider billing must be verified separately on provider dashboard. Confidence is not a calibrated probability.
