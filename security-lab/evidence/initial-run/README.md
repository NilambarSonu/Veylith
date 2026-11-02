# Initial measured run — preserved without relabeling

These gzip JSON files preserve the first holdout and corresponding development run at source commit `01ecb34`. No holdout input, label, expected result, policy pattern or model behavior changed afterward.

A measurement review found that the forwarding counter wrongly marked the explicitly authorized **recovery** call in development G3 outage testing as a forwarding violation. The same bookkeeping affected the compound outage/recovery driver. The corrected runner excludes those recovery actions from forbidden-forwarding counts; the driver independently verifies failed-phase call counts and recovery. Initial raw records remain here. This changes forwarding metrics, not classification labels or decisions.

The reconnect driver initially opened two clients concurrently. It was corrected to close the first before opening the second, so the final run exercises reconnection as specified. Other concurrent-client cases still run in parallel. No policy/model change was made from holdout failures.

The loaded regression log preserves a 193/194 run: an unchanged stdio test's fixed 1.5-second sleep observed no stdout while other test/evaluation jobs were running. It was not discarded or relabeled; final gates run without competing evaluation load. Initial latency numbers were also collected alongside other verification work and are not isolated capacity measurements.
