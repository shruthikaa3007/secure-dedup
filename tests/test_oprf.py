from src.crypto.oprf import blind, evaluate, finalize, full_oprf, unblind
from src.crypto.oprf_backends import HMACBackend, RISTRETTO_ELEMENT_BYTES, Ristretto255Backend


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


def test_ristretto_backend_blind_evaluate_unblind_produces_valid_finalize_input():
    epoch_key = b"r" * 32
    chunk = b"chunk-b"
    backend = Ristretto255Backend(server_secret=epoch_key)

    blinded_point, blinding_scalar = backend.blind(chunk)
    evaluated = backend.evaluate(blinded_point)
    unblinded = backend.unblind(evaluated, blinding_scalar)
    finalized = backend.finalize(unblinded, chunk, epoch=9)

    assert len(blinded_point) == RISTRETTO_ELEMENT_BYTES
    assert len(evaluated) == RISTRETTO_ELEMENT_BYTES * 2
    assert len(unblinded) == RISTRETTO_ELEMENT_BYTES
    assert len(finalized) == 32


def test_public_oprf_api_roundtrip_matches_full_oprf():
    epoch_key = b"z" * 32
    chunk = b"chunk-c"

    blinded_point, blinding_scalar = blind(chunk, epoch_key=epoch_key)
    evaluated = evaluate(blinded_point, epoch_key=epoch_key)
    unblinded = unblind(evaluated, blinding_scalar, epoch_key=epoch_key)
    manual = finalize(unblinded, chunk, epoch=11, epoch_key=epoch_key)
    direct = full_oprf(chunk, epoch=11, epoch_key=epoch_key)

    assert manual == direct


def test_hmac_backend_remains_available_for_explicit_fallback():
    backend = HMACBackend(server_secret=b"h" * 32)
    blinded_point, blinding_scalar = backend.blind(b"chunk-d")
    evaluated = backend.evaluate(blinded_point)
    assert backend.unblind(evaluated, blinding_scalar) == evaluated
