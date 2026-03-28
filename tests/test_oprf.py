import pytest

from src.crypto.oprf import full_oprf
from src.crypto.oprf_backends import Ristretto255Backend


def test_full_oprf_is_deterministic_for_same_epoch_and_key():
    epoch_key = b"k" * 32
    chunk = b"chunk-a"
    left = full_oprf(chunk, epoch=7, epoch_key=epoch_key)
    right = full_oprf(chunk, epoch=7, epoch_key=epoch_key)
    assert left == right
    assert len(left) == 32


def test_full_oprf_changes_across_epochs():
    epoch_key = b"k" * 32
    chunk = b"chunk-a"
    first = full_oprf(chunk, epoch=7, epoch_key=epoch_key)
    second = full_oprf(chunk, epoch=8, epoch_key=epoch_key)
    assert first != second


def test_ristretto_backend_is_a_documented_upgrade_path():
    backend = Ristretto255Backend(server_secret=b"r" * 32)
    with pytest.raises(NotImplementedError):
        backend.blind(b"chunk")
