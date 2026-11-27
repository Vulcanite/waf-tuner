# Results

These are early numbers from a small project. They show direction, not proof. Each table says where it comes from and what it does not show.

## Lab evaluation: prompt v8 vs v7

**Setup.** DeepSeek Flash, one call per CRS match, thinking enabled at `low` effort with escalation to `high` for uncertain verdicts, 8 calls in parallel. 75 requests from the lab-captured set (`eval/requests.jsonl`): 74 to the Flask Lab Shop, 1 to DVWA, giving 264 labelled matches (202 attack, 62 harmless). The v7 baseline is the earlier prompt at `high` effort, scored on the same matches.

| | v7, threshold 0.90 | v8, threshold 0.75 | v8, threshold 0.90 |
| --- | --- | --- | --- |
| Attack matches cleared as harmless | 1 / 202 | **0 / 202** | **0 / 202** |
| Attack matches detected | 198 / 202 | 200 / 202 | 200 / 202 |
| Harmless matches cleared | 38 / 62 | **51 / 62** | 38 / 62 |
| Harmless matches called attack | 3 | 11 | 11 |
| Harmless matches left uncertain | 21 | 0 | 13 |
| Invalid outputs | 0 | 0 | 0 |

- Every v8 verdict had all three explanation fields filled.
- 21 exclusions were drafted, none on an attack. 30 more false-positive verdicts were withheld by the server: 12 lacked a route fact, 9 lacked match evidence, 7 were chained rules, 2 could not be expressed as a rule.
- Cost: about 2,650 prompt tokens and 650 output tokens per match; 272 calls for 264 matches. Wall time 187 s.

**How to read it.** v8 is more decisive in both directions. It clears more harmless matches, and it calls more of them attacks: the 11 come from values that genuinely look like attacks, such as `union select hoodie` in a search box. The threshold is the main lever: at 0.90 the harmless clearing falls back to the baseline level. Model confidence is not calibrated, so keep 0.90 for production and treat 0.75 as a lab setting.

**What it does not show.** The lab set was written by the same people who wrote the prompt, it is Flask-heavy, and 75 requests is small. These recordings are not in the repository yet.

## Real-application benchmark: WordPress and Nextcloud

To get labels that we did not write, `eval/bench` runs WordPress and Nextcloud behind two WAFs: plain CRS, and CRS with the official CRS rule-exclusion plugin for that application. The same traffic goes through both. A match on normal use that the plugin removes is a false positive that the CRS maintainers already chose to exclude.

| | WordPress | Nextcloud |
| --- | --- | --- |
| Labelled matches | 608 | 244 |
| False positives the plugin excludes | 361 | 120 |
| False positives the plugin does not cover | 30 | 12 |
| True positives (attack traffic) | 217 | 112 |
| True positives the plugin also suppresses | 115 | 38 |
| Attacks the plugin hides completely | 12 | 6 |

The finding that matters: **the official plugins also hide real attacks.** They exclude whole fields, for example every CRS rule on the WordPress comment fields, even though the plugin file's own header says the comment field is not excluded. Full details are in [`eval/bench/README.md`](https://github.com/Vulcanite/waf-tuner/blob/master/eval/bench/README.md).

**Not done yet:** WAF Tuner's model has not been run on this benchmark. That run, and a measure of what WAF Tuner's own exclusions would let through, are next on the [roadmap](./roadmap.md).
