# Eval report — MiniMax-M3

Generated: 2026-09-18T03:16:52.515065+00:00
Prompt: `offpath-v5-classify` (`e87bbf2567b3`)

## Overall

- Fixtures: 19
- Schema valid: 19/19
- Repair rate: 10.5%
- Attack cases classified false_positive (miss): 0/13
- Benign accuracy (classified false_positive): 83.3%

| expected \ predicted | true_positive | false_positive | uncertain | invalid |
|---|---:|---:|---:|---:|
| attack | 13 | 0 | 0 | 0 |
| benign | 0 | 5 | 1 | 0 |

## Per CRS rule ID

| rule ID | n | attack | benign | attack miss (FP) | benign accuracy | uncertain |
|---|---:|---:|---:|---:|---:|---:|
| 930100 | 2 | 1 | 1 | 0 | 100.0% | 0 |
| 930110 | 1 | 1 | 0 | 0 | n/a | 0 |
| 930120 | 1 | 1 | 0 | 0 | n/a | 0 |
| 930130 | 1 | 1 | 0 | 0 | n/a | 0 |
| 931130 | 1 | 0 | 1 | 0 | 0.0% | 1 |
| 932100 | 2 | 1 | 1 | 0 | 100.0% | 0 |
| 932105 | 1 | 1 | 0 | 0 | n/a | 0 |
| 932110 | 1 | 1 | 0 | 0 | n/a | 0 |
| 941100 | 2 | 1 | 1 | 0 | 100.0% | 0 |
| 941110 | 1 | 1 | 0 | 0 | n/a | 0 |
| 941120 | 1 | 1 | 0 | 0 | n/a | 0 |
| 942100 | 3 | 1 | 2 | 0 | 100.0% | 0 |
| 942130 | 1 | 1 | 0 | 0 | n/a | 0 |
| 942160 | 1 | 1 | 0 | 0 | n/a | 0 |
