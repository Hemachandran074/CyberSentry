"""Unit tests for the bigram frequency baseline (objective 5.3)."""
import numpy as np
import pytest
from cybersentry_ml.sequence import baseline as freq


def test_the_frequency_baseline_is_not_rigged_to_lose():
    normal = [["logon", "read", "logoff"] for _ in range(50)]
    model = freq.fit(normal)
    short = freq.session_nll(["logon", "read", "logoff"], model)
    long_same = freq.session_nll(["logon", "read", "logoff"] * 10, model)
    # a mean, not a sum: a long normal session is not more anomalous
    assert long_same == pytest.approx(short, rel=0.25)
    odd = freq.session_nll(["psexec", "mimikatz", "logoff"], model)
    assert odd > short


def test_empty_sequence_returns_zero():
    model = freq.fit([["logon", "logoff"]])
    assert freq.session_nll([], model) == 0.0


def test_score_sessions():
    normal = [["logon", "file_open", "file_close", "logoff"] for _ in range(30)]
    model = freq.fit(normal)
    sessions = [
        ["logon", "file_open", "file_close", "logoff"],
        ["logon", "admin_escalate", "exfil", "logoff"],
    ]
    scores = freq.score_sessions(sessions, model)
    assert isinstance(scores, np.ndarray)
    assert len(scores) == 2
    # The anomalous session must have a higher NLL than the routine session
    assert scores[1] > scores[0]
