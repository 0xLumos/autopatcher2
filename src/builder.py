import os
import logging
import json
import time
import re
from functools import wraps
from contextlib import contextmanager
from typing import Tuple, Optional, Dict, Any
from .utils import run_cmd

logger = logging.getLogger("docker_patch_tool")

# Default build timeout in seconds
DEFAULT_BUILD_TIMEOUT = 600


def _categorize_build_error(output: str) -> str:
    """
    Categorize Docker build errors based on output patterns.

    Args:
        output: Docker build error output

    Returns:
        Error category string
    """
    output_lower = output.lower()

    if "base image" in output_lower and "not found" in output_lower:
        return "BASE_IMAGE_NOT_FOUND"
    elif "permission denied" in output_lower:
        return "PERMISSION_DENIED"
    elif "no such file or directory" in output_lower:
        return "FILE_NOT_FOUND"
    elif "bad syntax" in output_lower or "syntax error" in output_lower:
        return "DOCKERFILE_SYNTAX_ERROR"
    elif "failed to build" in output_lower:
        return "BUILD_FAILED"
    elif "network" in output_lower or "timeout" in output_lower:
        return "NETWORK_ERROR"
    else:
        return "UNKNOWN_ERROR"


def measure_build_time(func):
    """
    Decorator that measures and records build duration.

    Args:
        func: Function to decorate

    Returns:
        Wrapped function that records execution time
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start_time
        logger.info(f"{func.__name__} completed in {duration:.2f}s")
        return result
    return wrapper


@contextmanager
def build_timer(operation_name: str):
    """
    Context manager that measures and logs operation duration.

    Args:
        operation_name: Name of the operation being timed

    Yields:
        None
    """
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        logger.info(f"{operation_name} completed in {duration:.2f}s")


def measure_image_size(image_name: str) -> Optional[float]:
    """
    Measure the size of a Docker image in megabytes.

    Args:
        image_name: Name/tag of the Docker image

    Returns:
        Size in MB, or None if image not found or error occurs
    """
    logger.debug(f"Measuring size of image '{image_name}' ...")
    cmd = ["docker", "inspect", image_name, "--format", "{{.Size}}"]
    code, output = run_cmd(cmd)

    if code != 0:
        logger.error(f"Failed to inspect image {image_name}: {output}")
        return None

    try:
        size_bytes = int(output.strip())
        size_mb = size_bytes / (1024 * 1024)
        logger.debug(f"Image '{image_name}' size: {size_mb:.2f} MB")
        return size_mb
    except ValueError:
        logger.error(f"Failed to parse image size output: {output}")
        return None


def pull_image(image_name: str) -> bool:
    """
    Pull a Docker image from a registry.

    Args:
        image_name: Name/tag of the image to pull

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Pulling image '{image_name}' from registry ...")
    with build_timer(f"Image pull '{image_name}'"):
        code, output = run_cmd(["docker", "pull", image_name])

    if code != 0:
        logger.error(f"Failed to pull image {image_name}: {output}")
        return False

    logger.debug(f"Successfully pulled image '{image_name}'")
    return True


def remove_image(image_name: str, force: bool = False) -> bool:
    """
    Remove a Docker image.

    Args:
        image_name: Name/tag of the image to remove
        force: If True, force remove even if in use

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Removing image '{image_name}' ...")
    cmd = ["docker", "rmi"]
    if force:
        cmd.append("-f")
    cmd.append(image_name)

    code, output = run_cmd(cmd)
    if code != 0:
        logger.error(f"Failed to remove image {image_name}: {output}")
        return False

    logger.debug(f"Successfully removed image '{image_name}'")
    return True


def get_image_digest(image_name: str) -> Optional[str]:
    """
    Get the SHA256 digest of a Docker image.

    Args:
        image_name: Name/tag of the Docker image

    Returns:
        SHA256 digest string (e.g., 'sha256:abc123...'), or None if not found
    """
    logger.debug(f"Retrieving digest for image '{image_name}' ...")
    cmd = ["docker", "inspect", image_name, "--format", "{{.RepoDigests}}"]
    code, output = run_cmd(cmd)

    if code != 0:
        logger.error(f"Failed to inspect image {image_name} for digest: {output}")
        return None

    output = output.strip()

    # Output is usually in format [repo@sha256:xxx ...]
    # Extract the FULL reference (repo@sha256:xxx) because cosign needs
    # the complete image reference, not just the bare hash.
    full_ref_match = re.search(r'([\w./:_-]+@sha256:[a-f0-9]{64})', output)
    if full_ref_match:
        full_ref = full_ref_match.group(1)
        logger.debug(f"Image '{image_name}' digest ref: {full_ref}")
        return full_ref

    # Fallback: try bare digest (won't work for cosign but better than None)
    digest_match = re.search(r'sha256:[a-f0-9]{64}', output)
    if digest_match:
        digest = digest_match.group(0)
        logger.warning(f"Could only extract bare digest for '{image_name}': {digest}")
        return digest

    logger.warning(f"Could not extract digest from output: {output}")
    return None


@measure_build_time
def build_image(
    image_name: str,
    dockerfile_path: str,
    timeout: int = DEFAULT_BUILD_TIMEOUT
) -> Tuple[bool, Optional[str]]:
    """
    Build a Docker image with the given name (tag) from the specified Dockerfile.

    Args:
        image_name: Name/tag for the built image
        dockerfile_path: Path to the Dockerfile
        timeout: Build timeout in seconds (default: 600)

    Returns:
        Tuple of (success: bool, error_category: Optional[str])
        - success: True if build succeeds, False otherwise
        - error_category: If failed, the category of error; None if successful
    """
    context_dir = os.path.dirname(os.path.abspath(dockerfile_path)) or "."
    logger.info(f"Building image '{image_name}' from {dockerfile_path} (timeout: {timeout}s) ...")

    cmd = ["docker", "build", "-t", image_name, "-f", dockerfile_path, context_dir]

    with build_timer(f"Docker build '{image_name}'"):
        code, output = run_cmd(cmd, timeout=timeout)

    if code != 0:
        error_category = _categorize_build_error(output)
        logger.error(f"Docker build failed for {image_name} ({error_category}):\n{output}")
        return False, error_category

    logger.debug(f"Docker build output for {image_name}: {output}")
    return True, None


def tag_image(source_image: str, target_image: str) -> bool:
    """
    Tag a local Docker image with a new name/tag (usually for pushing to a registry).

    Args:
        source_image: Name/tag of the source image
        target_image: New name/tag for the image

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Tagging image '{source_image}' as '{target_image}' ...")
    code, output = run_cmd(["docker", "tag", source_image, target_image])

    if code != 0:
        logger.error(f"Failed to tag image {source_image} as {target_image}: {output}")
        return False

    logger.debug(f"Successfully tagged image as '{target_image}'")
    return True


def push_image(
    image_name: str,
    max_retries: int = 3,
    retry_delay: int = 5
) -> bool:
    """
    Push a Docker image to a registry with retry logic.

    The registry may be temporarily unavailable, so this function retries
    the push operation if it fails.

    Args:
        image_name: Name/tag of the image to push
        max_retries: Maximum number of retry attempts (default: 3)
        retry_delay: Delay between retries in seconds (default: 5)

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Pushing image '{image_name}' to registry (max_retries: {max_retries}) ...")

    for attempt in range(1, max_retries + 1):
        with build_timer(f"Image push '{image_name}' (attempt {attempt}/{max_retries})"):
            code, output = run_cmd(["docker", "push", image_name])

        if code == 0:
            logger.info(f"Successfully pushed image '{image_name}' on attempt {attempt}")
            return True

        logger.warning(f"Push attempt {attempt} failed: {output}")

        if attempt < max_retries:
            logger.info(f"Retrying in {retry_delay}s ...")
            time.sleep(retry_delay)

    logger.error(f"Failed to push image {image_name} after {max_retries} attempts")
    return False
