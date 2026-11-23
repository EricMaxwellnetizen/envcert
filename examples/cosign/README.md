# Cosign attestation policies

Example CUE/Rego policies for `cosign verify-attestation --policy`. They require the Envicert in-toto Test Result predicate and a PASSED result. Use with:

```bash
envicert check ./my-task --format json --output report.json --image myimage@sha256:<digest>
envicert attest report.json --image myimage@sha256:<digest> --key cosign.key
envicert verify-attestation attestation.json --image myimage@sha256:<digest> --key cosign.pub --policy examples/cosign/policy.cue
```

Referencing an image by tag instead of digest is refused by `envicert attest --image`: attestations must bind to immutable content.
