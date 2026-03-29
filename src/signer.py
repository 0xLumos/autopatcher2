import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")
COSIGN_PRIV_KEY = "cosign.key"
COSIGN_PUB_KEY = "cosign.pub"


# Custom exception types for better error handling
class SigningError(Exception):
    """Base exception for signing operations."""
    pass


class KeyGenerationError(SigningError):
    """Raised when Cosign key generation fails."""
    pass


class SignatureError(SigningError):
    """Raised when image signing fails."""
    pass


class VerificationError(SigningError):
    """Raised when signature verification fails."""
    pass


class AttestationError(SigningError):
    """Raised when attestation generation or attachment fails."""
    pass


class SBOMError(SigningError):
    """Raised when SBOM attachment fails."""
    pass


@dataclass
class SigningLog:
    """Structured log entry for signing operations."""
    timestamp: str
    image_ref: str
    signing_mode: str
    operation: str  # "sign", "verify", "attestation", "sbom", etc.
    success: bool
    duration_seconds: float
    error_message: Optional[str] = None


# Global signing log storage
_signing_logs: List[SigningLog] = []


def get_signing_log() -> List[Dict[str, Any]]:
    """
    Return the accumulated signing log entries as dictionaries.

    Returns:
        List of signing log entries as dictionaries with all operation details.
    """
    return [asdict(log) for log in _signing_logs]


def _record_signing_log(
    image_ref: str,
    signing_mode: str,
    operation: str,
    success: bool,
    duration_seconds: float,
    error_message: Optional[str] = None
) -> None:
    """
    Record a signing operation to the structured log.

    Args:
        image_ref: Docker image reference.
        signing_mode: "key", "keyless", or "none".
        operation: Type of operation ("sign", "verify", "attestation", "sbom").
        success: Whether the operation succeeded.
        duration_seconds: How long the operation took.
        error_message: Error details if operation failed.
    """
    log_entry = SigningLog(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        image_ref=image_ref,
        signing_mode=signing_mode,
        operation=operation,
        success=success,
        duration_seconds=duration_seconds,
        error_message=error_message
    )
    _signing_logs.append(log_entry)


def ensure_cosign_key() -> bool:
    """
    Ensure a local Cosign key pair exists (generate one if not).

    Returns:
        True if a key pair is ready (cosign.key and cosign.pub in current directory).

    Raises:
        KeyGenerationError: If key generation fails.
    """
    if os.path.exists(COSIGN_PRIV_KEY) and os.path.exists(COSIGN_PUB_KEY):
        return True
    logger.info("Generating Cosign key pair for signing (no passphrase)...")
    code, output = run_cmd(
        ["cosign", "generate-key-pair", "--output-key-prefix", "cosign"],
        env_override={"COSIGN_PASSWORD": ""}
    )
    if code != 0:
        error_msg = f"Cosign key generation failed:\n{output}"
        logger.error(error_msg)
        raise KeyGenerationError(error_msg)
    return True


def sign_image(image_ref: str, signing_mode: str) -> bool:
    """
    Sign the given image reference using Cosign.

    Args:
        image_ref: Docker image reference (digest format recommended).
        signing_mode: "key" for local key, "keyless" for Sigstore keyless (OIDC),
                     "none" to skip signing.

    Returns:
        True on successful signing (or if signing skipped with "none").

    Raises:
        SignatureError: If signing fails.
        KeyGenerationError: If key generation fails (for "key" mode).
    """
    start_time = time.time()
    error_message = None

    try:
        if signing_mode == "none":
            logger.info("Signing skipped (mode=none).")
            duration = time.time() - start_time
            _record_signing_log(image_ref, signing_mode, "sign", True, duration)
            return True

        if signing_mode == "key":
            # Local key signing — needs COSIGN_PASSWORD for non-interactive use
            ensure_cosign_key()
            logger.info(f"Signing image {image_ref} with Cosign (local key)...")
            env = {"COSIGN_PASSWORD": ""}
            code, output = run_cmd([
                "cosign", "sign", "--yes",
                "--allow-insecure-registry", "--allow-http-registry",
                "--key", COSIGN_PRIV_KEY, image_ref
            ], env_override=env)
        elif signing_mode == "keyless":
            # Keyless signing using OIDC
            logger.info(f"Signing image {image_ref} with Cosign (keyless)...")
            env = {"COSIGN_EXPERIMENTAL": "1"}
            code, output = run_cmd([
                "cosign", "sign", "--yes",
                "--allow-insecure-registry", "--allow-http-registry",
                image_ref
            ], env_override=env)
        else:
            raise SignatureError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Image signing failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "sign", False, duration, error_message)
            raise SignatureError(error_message)

        logger.info("Image signed successfully.")
        _record_signing_log(image_ref, signing_mode, "sign", True, duration)
        return True

    except SignatureError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "sign", False, duration, error_message)
        raise SignatureError(f"Unexpected error during signing: {error_message}")


def verify_image(image_ref: str, signing_mode: str) -> bool:
    """
    Verify the signature of the given image reference using Cosign.

    Args:
        image_ref: Docker image reference.
        signing_mode: "key" for local key verification, "keyless" for Sigstore keyless.

    Returns:
        True if verification succeeds.

    Raises:
        VerificationError: If verification fails.
    """
    start_time = time.time()
    error_message = None

    try:
        logger.info("Verifying image signature...")
        if signing_mode == "key":
            cmd = [
                "cosign", "verify",
                "--allow-insecure-registry", "--allow-http-registry",
                "--key", COSIGN_PUB_KEY, image_ref
            ]
            code, output = run_cmd(cmd)
        elif signing_mode == "keyless":
            env = {"COSIGN_EXPERIMENTAL": "1"}
            cmd = [
                "cosign", "verify",
                "--allow-insecure-registry", "--allow-http-registry",
                image_ref
            ]
            code, output = run_cmd(cmd, env_override=env)
        else:
            raise VerificationError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Signature verification failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "verify", False, duration, error_message)
            raise VerificationError(error_message)

        logger.info("Signature verification passed.")
        _record_signing_log(image_ref, signing_mode, "verify", True, duration)
        return True

    except VerificationError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "verify", False, duration, error_message)
        raise VerificationError(f"Unexpected error during verification: {error_message}")


def generate_attestation(
    image_ref: str,
    predicate_path: str,
    predicate_type: str = "slsaprovenance"
) -> bool:
    """
    Generate and attach a SLSA provenance attestation to the image.

    Args:
        image_ref: Docker image reference (digest format recommended).
        predicate_path: Path to the predicate file (JSON).
        predicate_type: Type of attestation predicate (default: "slsaprovenance").

    Returns:
        True if attestation generation succeeds.

    Raises:
        AttestationError: If attestation generation fails.
    """
    start_time = time.time()
    error_message = None

    try:
        if not os.path.exists(predicate_path):
            raise AttestationError(f"Predicate file not found: {predicate_path}")

        logger.info(f"Generating {predicate_type} attestation for {image_ref}...")
        logger.info(f"Using predicate from: {predicate_path}")

        code, output = run_cmd([
            "cosign", "attest", "--yes",
            "--allow-insecure-registry", "--allow-http-registry",
            "--predicate", predicate_path,
            "--type", predicate_type,
            image_ref
        ])

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Attestation generation failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, "keyless", "attestation", False, duration, error_message)
            raise AttestationError(error_message)

        logger.info(f"Attestation generated and attached successfully.")
        _record_signing_log(image_ref, "keyless", "attestation", True, duration)
        return True

    except AttestationError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, "keyless", "attestation", False, duration, error_message)
        raise AttestationError(f"Unexpected error during attestation: {error_message}")


def attach_sbom(
    image_ref: str,
    sbom_path: str,
    signing_mode: str
) -> bool:
    """
    Attach an SBOM (Software Bill of Materials) to the image.

    Args:
        image_ref: Docker image reference (digest format recommended).
        sbom_path: Path to the SBOM file (typically in SPDX JSON format).
        signing_mode: "key" for local key, "keyless" for Sigstore keyless.

    Returns:
        True if SBOM attachment succeeds.

    Raises:
        SBOMError: If SBOM attachment fails.
    """
    start_time = time.time()
    error_message = None

    try:
        if not os.path.exists(sbom_path):
            raise SBOMError(f"SBOM file not found: {sbom_path}")

        logger.info(f"Attaching SBOM to {image_ref}...")
        logger.info(f"Using SBOM from: {sbom_path}")

        # cosign attach sbom does NOT take --key; it simply attaches the
        # SBOM as an OCI artifact.  Signing the SBOM is a separate step.
        if signing_mode in ("key", "keyless"):
            code, output = run_cmd([
                "cosign", "attach", "sbom",
                "--allow-insecure-registry", "--allow-http-registry",
                "--sbom", sbom_path,
                image_ref
            ])
        else:
            raise SBOMError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"SBOM attachment failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(image_ref, signing_mode, "sbom", False, duration, error_message)
            raise SBOMError(error_message)

        logger.info("SBOM attached successfully.")
        _record_signing_log(image_ref, signing_mode, "sbom", True, duration)
        return True

    except SBOMError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "sbom", False, duration, error_message)
        raise SBOMError(f"Unexpected error during SBOM attachment: {error_message}")


def verify_attestation(image_ref: str, signing_mode: str) -> bool:
    """
    Verify attestations attached to the image.

    Args:
        image_ref: Docker image reference.
        signing_mode: "key" for local key verification, "keyless" for Sigstore keyless.

    Returns:
        True if attestation verification succeeds.

    Raises:
        VerificationError: If attestation verification fails.
    """
    start_time = time.time()
    error_message = None

    try:
        logger.info("Verifying image attestations...")
        if signing_mode == "key":
            cmd = [
                "cosign", "verify-attestation",
                "--allow-insecure-registry", "--allow-http-registry",
                "--key", COSIGN_PUB_KEY,
                image_ref
            ]
            code, output = run_cmd(cmd)
        elif signing_mode == "keyless":
            env = {"COSIGN_EXPERIMENTAL": "1"}
            cmd = [
                "cosign", "verify-attestation",
                "--allow-insecure-registry", "--allow-http-registry",
                image_ref
            ]
            code, output = run_cmd(cmd, env_override=env)
        else:
            raise VerificationError(f"Unknown signing mode: {signing_mode}")

        duration = time.time() - start_time
        if code != 0:
            error_message = f"Attestation verification failed:\n{output}"
            logger.error(error_message)
            _record_signing_log(
                image_ref, signing_mode, "verify_attestation", False, duration, error_message
            )
            raise VerificationError(error_message)

        logger.info("Attestation verification passed.")
        _record_signing_log(image_ref, signing_mode, "verify_attestation", True, duration)
        return True

    except VerificationError:
        raise
    except Exception as e:
        duration = time.time() - start_time
        error_message = str(e)
        _record_signing_log(image_ref, signing_mode, "verify_attestation", False, duration, error_message)
        raise VerificationError(f"Unexpected error during attestation verification: {error_message}")
