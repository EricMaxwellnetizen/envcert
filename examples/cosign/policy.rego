package sigstore

default allow = false

allow if {
	input.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
	input.predicate.result == "PASSED"
}
