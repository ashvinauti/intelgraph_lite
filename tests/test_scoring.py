from iglite.model import Evidence, Verdict
from iglite.scoring import assess

TRUST = {"a": 0.8, "b": 0.7, "allow": 0.9, "weak": 0.2}


def ev(src, verdict, conf=1.0):
    return Evidence(src, verdict, f"{src} says {verdict.value}", conf)


def test_no_evidence_is_unknown():
    a = assess([], TRUST)
    assert a.verdict is Verdict.UNKNOWN and a.score < 20 and not a.reasons


def test_single_source_is_only_suspicious():
    a = assess([ev("a", Verdict.MALICIOUS)], TRUST)
    assert a.verdict is Verdict.SUSPICIOUS


def test_corroboration_makes_malicious():
    a = assess([ev("a", Verdict.MALICIOUS), ev("b", Verdict.MALICIOUS)], TRUST)
    assert a.verdict is Verdict.MALICIOUS and a.score >= 90
    assert [r.source for r in a.reasons] == ["a", "b"]  # strongest first


def test_one_source_cannot_stack_votes():
    many = [ev("a", Verdict.MALICIOUS, 0.5)] * 20
    assert assess(many, TRUST).score == assess(many[:1], TRUST).score


def test_contradiction_is_flagged():
    a = assess([ev("b", Verdict.MALICIOUS), ev("allow", Verdict.BENIGN)], TRUST)
    assert a.contradiction
    assert a.verdict is Verdict.BENIGN


def test_neighbour_is_a_hint_not_a_conviction():
    alone = assess([], TRUST, [("ip:1.2.3.4", "resolves_to")])
    assert alone.verdict is Verdict.UNKNOWN
    assert alone.reasons[0].source == "graph"
    many = assess([], TRUST, [("ip:1.2.3.4", "resolves_to")] * 10)
    assert many.score == alone.score
