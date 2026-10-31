"""GRU next-event model (FR-7).

Trained on attack-free segments ONLY - it learns what normal looks like and
scores a session by how surprised it is. That framing matters: a classifier
trained on labelled attacks learns the attacks in the dataset, and the attack
that matters is the one nobody has labelled yet.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping, Sequence
import numpy as np
import torch
from torch import nn

PAD, UNK = 0, 1


class NextEventGRU(nn.Module):
    """Predicts next-action logits from an action token sequence."""

    def __init__(
        self,
        vocab_size: int,
        embed: int = 64,
        hidden: int = 128,
        layers: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed, padding_idx=PAD)
        self.gru = nn.GRU(
            embed,
            hidden,
            layers,
            batch_first=True,
            dropout=dropout if layers > 1 else 0.0,
        )
        self.head = nn.Linear(hidden, vocab_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out, _ = self.gru(self.embedding(x))
        return self.head(out)


def build_vocab(
    sequences: Iterable[Sequence[str]],
    min_count: int = 5,
) -> dict[str, int]:
    """Rare actions collapse to UNK. Without it the model memorises a handful of
    one-off actions and then scores every genuinely novel action as familiar -
    the opposite of what an anomaly detector is for.
    """
    counts: Counter[str] = Counter(a for s in sequences for a in s)
    vocab = {"<pad>": PAD, "<unk>": UNK}
    for action, n in sorted(counts.items()):
        if n >= min_count:
            vocab[action] = len(vocab)
    return vocab


def encode(sequence: Sequence[str], vocab: Mapping[str, int], max_len: int = 128) -> np.ndarray:
    """Encode an action sequence into a fixed-length right-aligned, left-padded array."""
    ids = [vocab.get(str(a), UNK) for a in sequence][-max_len:]
    return np.array([PAD] * (max_len - len(ids)) + ids, dtype=np.int64)


@torch.no_grad()
def session_nll(
    model: nn.Module,
    encoded: np.ndarray,
    device: str = "cpu",
) -> np.ndarray:
    """Mean negative log-likelihood per REAL event, padding excluded.

    The same per-event mean the frequency baseline uses, so the two are comparable -
    comparing a sum against a mean would hand the GRU a free win on long
    sessions and make the 20% lift meaningless.
    """
    model.eval().to(device)
    x = torch.as_tensor(encoded, dtype=torch.long, device=device)
    if x.dim() == 1:
        x = x.unsqueeze(0)

    logits = model(x[:, :-1])
    targets = x[:, 1:]
    logp = torch.log_softmax(logits, dim=-1)
    gathered = logp.gather(-1, targets.unsqueeze(-1)).squeeze(-1)
    mask = targets != PAD
    counts = mask.sum(dim=1).clamp(min=1)

    nll = (-(gathered * mask).sum(dim=1) / counts).cpu().numpy()
    return nll


def calibration_for(nll_values: Sequence[float] | np.ndarray) -> dict[str, Any]:
    """Per-entity mean and std of attack-free NLL - what fusion normalises
    against. Stored with the model so serving cannot drift from training.
    """
    v = np.asarray(nll_values, dtype=float)
    return {
        "mean": float(v.mean()) if v.size else 0.0,
        "std": float(v.std()) if v.size and v.std() > 0 else 1.0,
        "n": int(v.size),
    }
