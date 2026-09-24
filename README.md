# airrow-rules

Public rules for detections.

## Repository layout

- `/rules` contains individual rule definitions
- `/schemas/rule.schema.json` defines the rule contract
- `/channels/stable.json` declares the rules shipped in the stable channel
- `/scripts/build_bundle.py` validates rules and builds a bundle for a channel
