# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent the detects, analyzes, and resolves CI/CD failures in real-time.

import io
import uuid
from typing import Optional, BinaryIO
import boto3
from botocore.exceptions import ClientError
from botocore.client import Config
import structlog

from app.core.config import settings

logger = structlog.get_logger()


class BackblazeStorageService:
    """Service for uploading files to Backblaze B2 bucket."""

    def __init__(self):
        """Initialize Backblaze B2 client using S3-compatible API."""
        self.bucket_name = settings.backblaze.bucket_name
        self.region = settings.backblaze.region

        # Initialize S3 client with Backblaze B2 endpoint
        self.s3_client = boto3.client(
            's3',
            endpoint_url=settings.backblaze.endpoint_url,
            aws_access_key_id=settings.backblaze.key_id,
            aws_secret_access_key=settings.backblaze.application_key,
            config=Config(signature_version='s3v4'),
            region_name=self.region
        )

        logger.info(
            "backblaze_storage_initialized",
            bucket_name=self.bucket_name,
            region=self.region
        )

    def upload_avatar(
        self,
        file_content: bytes,
        user_id: str,
        content_type: str = "image/png"
    ) -> str:
        """
        Upload user avatar to Backblaze B2 bucket.

        Args:
            file_content: Binary content of the image file
            user_id: Unique user identifier
            content_type: MIME type of the image (e.g., image/png, image/jpeg)

        Returns:
            Public URL of the uploaded file

        Raises:
            Exception: If upload fails
        """
        try:
            # Create unique filename using user_id and a UUID to allow multiple uploads
            file_extension = self._get_file_extension(content_type)
            filename = f"user_profile/{user_id}_{uuid.uuid4().hex}{file_extension}"

            logger.info(
                "uploading_avatar_to_b2",
                user_id=user_id,
                filename=filename,
                content_type=content_type,
                size_bytes=len(file_content)
            )

            # Upload file to B2
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=filename,
                Body=file_content,
                ContentType=content_type,
                ACL='public-read'  # Make file publicly accessible
            )

            # Generate public URL
            public_url = f"{settings.backblaze.endpoint_url}/{self.bucket_name}/{filename}"

            logger.info(
                "avatar_uploaded_successfully",
                user_id=user_id,
                public_url=public_url
            )

            return public_url

        except ClientError as e:
            logger.error(
                "backblaze_upload_failed",
                user_id=user_id,
                error=str(e),
                error_code=e.response.get('Error', {}).get('Code')
            )
            raise Exception(f"Failed to upload avatar to Backblaze: {str(e)}")
        except Exception as e:
            logger.error(
                "unexpected_upload_error",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            raise Exception(f"Unexpected error during avatar upload: {str(e)}")

    def delete_avatar(self, file_url: str) -> bool:
        """
        Delete an avatar file from Backblaze B2 bucket.

        Args:
            file_url: Public URL of the file to delete

        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            # Extract filename from URL
            filename = self._extract_filename_from_url(file_url)

            if not filename:
                logger.warning("invalid_file_url", file_url=file_url)
                return False

            logger.info("deleting_avatar_from_b2", filename=filename)

            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=filename
            )

            logger.info("avatar_deleted_successfully", filename=filename)
            return True

        except ClientError as e:
            logger.error(
                "backblaze_delete_failed",
                filename=filename,
                error=str(e),
                error_code=e.response.get('Error', {}).get('Code')
            )
            return False
        except Exception as e:
            logger.error(
                "unexpected_delete_error",
                error=str(e),
                error_type=type(e).__name__
            )
            return False

    def _get_file_extension(self, content_type: str) -> str:
        """Get file extension from content type."""
        content_type_map = {
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/jpg": ".jpg",
            "image/gif": ".gif",
            "image/webp": ".webp",
            "image/svg+xml": ".svg"
        }
        return content_type_map.get(content_type.lower(), ".png")

    def _extract_filename_from_url(self, file_url: str) -> Optional[str]:
        """Extract filename from Backblaze public URL."""
        try:
            # URL format: https://endpoint/bucket/filename
            parts = file_url.split(f"/{self.bucket_name}/")
            if len(parts) == 2:
                return parts[1]
            return None
        except Exception:
            return None


def get_storage_service() -> BackblazeStorageService:
    """
    Get instance of Backblaze storage service.

    Returns:
        BackblazeStorageService instance
    """
    return BackblazeStorageService()
