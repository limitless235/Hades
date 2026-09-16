# Research report template

Fill after measured results exist. Do not claim the system is “secure.”

## Abstract

Security Without Refusal: Defense-in-Depth for Non-Refusing Enterprise LLMs

## Outline

1. Introduction — refusal ≠ authorization
2. Threat model — see `docs/threat-model.md`
3. Experimental environment — Aperture Systems, abliterated Qwen 3.5 4B, mock baseline
4. Baseline (D0) measurements
5. Defense iterations D1–D6 / D7
6. Results — ASR, utility, FPR, URR, SDR, PLR; security vs utility
7. Failure analysis — formatting / encoding / semantic / partial / aggregation (categories only)
8. Architectural lessons — never delegate authz to the model
9. Limitations
10. Conclusion

Paste tables from `eval/results/summary.csv` here after runs.
