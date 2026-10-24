# Prior work and the proposed contribution

This document records what was reviewed before making any novelty claim. The
conclusion is deliberately modest: the individual ingredients exist in the
literature. The contribution offered here is a specific **combination and
evaluation**, not the invention of graph correlation or adaptive honeypots.

## Reviewed directions

| Direction | Representative work | What it establishes |
| --- | --- | --- |
| Cyber threat attribution | Prasad et al., "A survey of cyber threat attribution" (Computers & Security, 2025) | Attribution is multi-signal and uncertainty-laden; technical indicators alone are weak |
| Cross-campaign attacker re-identification | "ARCANE: Cross-Campaign Attacker Re-identification via passive beacon telemetry" (arXiv, 2026) | Re-identification across campaigns is an active research problem and is feasible from passive behavioural telemetry |
| Behavioural actor profiling | Böge et al., "Unveiling Cyber Threat Actors: A Hybrid Deep Learning Approach" (ACM, 2025) | Behavioural profiling can cluster actor activity, but requires labelled data and offers limited per-decision explanation |
| Explainable graph detection | Shin et al., "Graph-Based Intrusion Detection with Explainable Edge Classification" (CMC, 2025) | Graph structure plus edge-level explanations improves analyst trust |
| Provenance-graph attribution | Jiang et al., "Orthrus: Achieving High Quality of Attribution" (USENIX Security, 2025) | Provenance graphs give high-fidelity causal attribution on hosts |
| Adaptive deception | Morozov et al., "The sweet taste of IoT deception: an adaptive honeypot framework" (JEC, 2024); Morić et al., "Advancing Cybersecurity with Honeypots and Deception Strategies" (MDPI, 2025) | Adaptive decoys are established; evaluation of when adaptation helps is less developed |
| Honeypot effectiveness measurement | Rowe, "Measuring the Effectiveness of Honeypot Counter-Deception" (NPS, 2006) | Metrics for decoy value exist and should be reported, not assumed |

## Gap identified

The reviewed work leaves a practical gap at the intersection of four
requirements:

1. correlation across **different source IPs** using behavioural evidence rather
   than IP identity;
2. **explicit, per-edge evidence** with contradictions and missing-data
   accounting, so an analyst can audit why two sessions were linked;
3. **corpus-relative** evidence weighting, so ubiquitous artefacts (default
   usernames, stock SSH clients, common scanner paths) do not create links;
4. **uncertainty-directed observation**, where additional decoy observation is
   requested only for ambiguous relationships and its effect is measured
   against passive collection.

Existing systems typically satisfy one or two of these. Provenance graphs give
strong causality but require host instrumentation; behavioural clustering
gives grouping but often not auditable per-pair reasons; adaptive honeypots
adapt without a formal uncertainty loop tied to a correlation graph.

## Contribution as implemented

A cross-IP evidence graph in which:

- sessions are compared over six evidence families — behaviour, targeting,
  timing, identity, verified intelligence and toolchain;
- tokens are weighted by document frequency in the analysed window, and
  tokens present in most sessions are excluded as uninformative;
- the evidence families themselves are scaled by that same corpus statistic,
  so a family whose tokens are almost all ubiquitous (generic shell commands,
  a stock client string) contributes less than one that still separates
  sessions in this window;
- a link requires both a numeric threshold and a **high-specificity anchor**
  (verified indicator, matching command structure, or shared credential plus
  client signature);
- contradictions reduce confidence and are stored on the edge;
- every edge records the algorithm version, the evidence context, missing
  families, and a human-readable explanation;
- uncertain edges can trigger a bounded, audited decoy investigation whose
  before/after confidence is recorded;
- severity, confidence and asset risk are separate outputs.

## Falsifiable hypothesis

> On telemetry where campaigns leave at least one distinguishing artefact,
> evidence-weighted correlation with corpus-relative weighting and anchors
> links related sessions across IPs with materially higher precision than a
> rule-based behavioural baseline, without collapsing recall, and additional
> decoy observation improves recall on uncertain pairs without a
> disproportionate increase in false positives.

This is falsified if precision is not materially higher than the rule baseline,
or if adaptive observation fails to improve recall, or if the improvement
disappears under ablation. The correlation clause holds on the synthetic
benchmark: precision is 1.000 against 0.066 for the rule baseline, with recall
0.81 and 0.56. The adaptive clause does **not** hold once the simulation stops
injecting a shared constant: additional observation moves almost no decisions
(one link gained and one lost per seed, four gained and two lost at volume, no
new false positives). The uniform-weight ablation reproduces the previous
model, so the small recall gain from corpus-relative family weighting is
visible rather than assumed. Full tables, including a seed where the
intelligence-family ablation performs slightly better, are in
`docs/research/evaluation-results.md`. The result remains unverified on
production telemetry.

## What is not claimed

- No claim that the method identifies a person, group or state actor.
- No claim that behavioural similarity proves common control.
- No claim that the confidence index is a calibrated probability.
- No claim that the synthetic benchmark generalises to all real networks.
- No claim that adaptive deception is novel in itself.
