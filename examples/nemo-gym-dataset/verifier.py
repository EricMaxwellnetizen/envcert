def verify(response=None, task_data=None, **kwargs):
    """Score a row: exact match against the row's expected answer."""
    if response is None or task_data is None:
        return 0.0
    expected = str(task_data.get("expected_answer", "")).strip()
    got = str(response).strip()
    assert expected != "", "row is missing expected_answer"
    return 1.0 if got == expected else 0.0
