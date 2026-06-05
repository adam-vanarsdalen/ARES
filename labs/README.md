# ARES Local Demo Labs

These services are intentionally vulnerable, contain only synthetic data, bind
to localhost, and are authorized only for the ARES lab profiles.

```bash
make demo-lab-up
make demo-run-researcher
make demo-run-government
make demo-report
make demo-lab-down
```

The aggregate lab is `http://127.0.0.1:8080`. Individual behaviors are also
available on ports `18101` through `18107`.

Researcher demo output emphasizes advanced verification, evidence, confidence,
reportability, and manual next tests. Government demo output emphasizes RoE
decisions, blocked actions, audit chain, standards mappings, STIX, and OSCAL.

No real credentials or public target dependencies are used.
