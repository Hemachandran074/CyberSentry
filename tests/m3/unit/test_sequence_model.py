"""Unit tests for the GRU next-event model (FR-7)."""
import numpy as np
import torch
from cybersentry_ml.sequence import model as seq_model


def test_build_vocab_collapses_rare_actions():
    # 'common' appears 6 times (>= 5), 'rare' appears 2 times (< 5)
    seqs = [["common", "common", "common"], ["common", "common", "common", "rare", "rare"]]
    vocab = seq_model.build_vocab(seqs, min_count=5)
    assert vocab["<pad>"] == 0
    assert vocab["<unk>"] == 1
    assert "common" in vocab
    assert "rare" not in vocab


def test_encode_pads_and_truncates():
    vocab = {"<pad>": 0, "<unk>": 1, "logon": 2, "read": 3}
    encoded = seq_model.encode(["logon", "read"], vocab, max_len=5)
    assert len(encoded) == 5
    assert list(encoded) == [0, 0, 0, 2, 3]

    # Unseen token maps to UNK (1)
    encoded_unk = seq_model.encode(["logon", "unknown_action"], vocab, max_len=4)
    assert list(encoded_unk) == [0, 0, 2, 1]


def test_gru_forward_and_session_nll():
    vocab_size = 10
    gru = seq_model.NextEventGRU(vocab_size=vocab_size, embed=16, hidden=32, layers=1)

    # Batch of 2 sessions of max_len 8
    encoded = np.array([
        [0, 0, 0, 0, 2, 3, 4, 5],
        [0, 0, 2, 3, 2, 3, 2, 3],
    ], dtype=np.int64)

    nll = seq_model.session_nll(gru, encoded)
    assert isinstance(nll, np.ndarray)
    assert len(nll) == 2
    assert all(val > 0 for val in nll)

    # 1D single-session test
    nll_1d = seq_model.session_nll(gru, encoded[0])
    assert len(nll_1d) == 1
    assert np.isclose(nll_1d[0], nll[0])


def test_calibration_for():
    vals = [2.0, 2.5, 3.0, 3.5, 4.0]
    cal = seq_model.calibration_for(vals)
    assert cal["n"] == 5
    assert np.isclose(cal["mean"], 3.0)
    assert cal["std"] > 0
