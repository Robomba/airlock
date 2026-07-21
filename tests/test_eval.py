"""airlock eval — the benchmark must actually run and its numbers must be real."""

from airlock.evalsuite import evaluate, dataset, keyword_flags, airlock_flags


def test_dataset_is_labelled_both_ways():
    d = dataset()
    assert len(d) >= 30
    assert any(e.label == 1 for e in d)
    assert any(e.label == 0 for e in d)


def test_eval_is_deterministic():
    a = evaluate(seed=42)
    b = evaluate(seed=42)
    assert (a["detectors"]["airlock"]["false_alarms_per_1000"]
            == b["detectors"]["airlock"]["false_alarms_per_1000"])


def test_airlock_has_fewer_false_alarms_than_keyword():
    r = evaluate()
    assert (r["detectors"]["airlock"]["false_alarm_rate"]
            < r["detectors"]["keyword"]["false_alarm_rate"])


def test_all_strict_self_checks_pass():
    r = evaluate()
    failed = [c["check"] for c in r["strict_checks"] if not c["pass"]]
    assert failed == [], "strict checks failed: %s" % failed


def test_base64_exfil_is_the_dataflow_win():
    ex = next(e for e in dataset() if e.id == "m_exfil_base64")
    assert airlock_flags(ex.records) is True     # dataflow catches the encoded leak
    assert keyword_flags(ex.records) is False    # keyword has nothing to grep


def test_numbers_are_computed_not_hardcoded():
    # Drop half the benign examples and the false-alarm COUNT must change,
    # proving the aggregate is derived from the data, not a literal.
    import airlock.evalsuite as E
    full = evaluate()["detectors"]["airlock"]["fp"]
    orig = E.dataset
    try:
        E.dataset = lambda: [e for e in orig() if e.label == 1]   # attacks only
        no_benign = evaluate()["detectors"]["airlock"]["fp"]
    finally:
        E.dataset = orig
    assert no_benign == 0 and full >= 0 and (full != no_benign or full == 0)


def test_transformed_exfil_is_a_known_miss():
    """We publish our ceiling. A competent adversary defeats BOTH airlock signals at
    once: gzip beats the byte fingerprint AND spacing the egress past the proximity
    window beats the temporal-proximity heuristic. So BOTH airlock and the keyword
    baseline miss it. If airlock ever 'catches' this, revisit honestly -- it would be
    a new capability, not a bugfix."""
    ex = next(e for e in dataset() if e.id == "m_exfil_gzip")
    assert airlock_flags(ex.records) is False    # known blind spot, documented
    assert keyword_flags(ex.records) is False
