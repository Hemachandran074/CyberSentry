"""Unit tests for sequence training pipeline and data chunking (FR-7)."""
from cybersentry_ml.sequence import train_sequence


def test_load_params_sequence():
    params = train_sequence.load_params()
    assert "seed" in params
    assert "max_len" in params
    assert "embed" in params
    assert "hidden" in params
    assert "layers" in params


def test_create_chunks():
    short_seqs = [["logon", "read", "logoff"], ["logon"]]
    chunks = train_sequence.create_chunks(short_seqs, max_len=10)
    # Sequence with length 1 is discarded, length 3 is kept
    assert len(chunks) == 1
    assert chunks[0] == ["logon", "read", "logoff"]

    # Long sequence of 20 elements with max_len 8
    long_seq = [f"act_{i}" for i in range(20)]
    chunks_long = train_sequence.create_chunks([long_seq], max_len=8)
    assert len(chunks_long) >= 2
    for c in chunks_long:
        assert len(c) <= 8
        assert len(c) >= 2
