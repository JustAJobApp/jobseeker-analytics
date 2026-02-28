"""AWS KMS-based encryption utilities for OAuth token storage."""

import base64
import logging

from utils.config_utils import get_settings


logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    pass


def _get_kms_client():
    """Initialize the boto3 KMS client with explicit Infisical secrets."""
    settings = get_settings()
    
    # Explicitly pass the custom named credentials to boto3
    return boto3.client(
        'kms',
        region_name=settings.AWS_DATABASE_REGION,
        aws_access_key_id=settings.AWS_KMS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_KMS_SECRET_ACCESS_KEY
    )


def encrypt_token(plaintext: str) -> str:
    import boto3
    from botocore.exceptions import ClientError
    """Encrypt a token by sending it directly to AWS KMS."""
    if not plaintext:
        raise EncryptionError("Cannot encrypt empty token")

    settings = get_settings()
    
    if not settings.is_publicly_deployed or settings.AWS_KMS_KEY_ARN == "default-for-local":
        return f"local_enc_{plaintext}"

    try:
        kms = _get_kms_client()
        response = kms.encrypt(
            KeyId=settings.AWS_KMS_KEY_ARN,
            Plaintext=plaintext.encode("utf-8")
        )
        return base64.b64encode(response["CiphertextBlob"]).decode("utf-8")
    except ClientError as e:
        logger.error("AWS KMS Encryption failed: %s", e.response['Error']['Code'])
        raise EncryptionError("Failed to encrypt token via KMS")


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a token by sending the ciphertext to AWS KMS."""
    if not ciphertext:
        raise EncryptionError("Cannot decrypt empty ciphertext")

    settings = get_settings()

    if not settings.is_publicly_deployed and ciphertext.startswith("local_enc_"):
        return ciphertext.replace("local_enc_", "")

    try:
        kms = _get_kms_client()
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        response = kms.decrypt(
            CiphertextBlob=ciphertext_bytes,
            KeyId=settings.AWS_KMS_KEY_ARN
        )
        return response["Plaintext"].decode("utf-8")
    except ClientError as e:
        logger.error("AWS KMS Decryption failed: %s", e.response['Error']['Code'])
        raise EncryptionError("Failed to decrypt token via KMS")