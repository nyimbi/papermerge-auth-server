# (c) Copyright Datacraft, 2026
"""MFA service for managing multi-factor authentication."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel

from .backup import BackupCodeManager, default_backup_manager
from .totp import TOTPManager, TOTPSetup, default_totp_manager


class MFAMethod(str, Enum):
	"""Supported MFA methods."""
	TOTP = "totp"
	SMS = "sms"
	EMAIL = "email"
	BACKUP_CODE = "backup_code"
	WEBAUTHN = "webauthn"


class MFAStatus(str, Enum):
	"""MFA enrollment status."""
	NOT_ENROLLED = "not_enrolled"
	PENDING = "pending"
	ENABLED = "enabled"
	DISABLED = "disabled"


class MFAEnrollment(BaseModel):
	"""MFA enrollment record."""
	user_id: uuid.UUID
	method: MFAMethod
	status: MFAStatus
	secret_encrypted: str | None = None  # Encrypted TOTP secret
	backup_codes_hashes: list[str] = []
	backup_codes_used: list[int] = []
	phone_number: str | None = None  # For SMS
	created_at: datetime
	enabled_at: datetime | None = None
	last_used_at: datetime | None = None


class MFASetupResponse(BaseModel):
	"""Response for MFA setup initiation."""
	enrollment_id: uuid.UUID
	method: MFAMethod
	totp_setup: TOTPSetup | None = None
	backup_codes: list[str] | None = None


class MFAVerifyRequest(BaseModel):
	"""Request to verify MFA code."""
	code: str
	method: MFAMethod = MFAMethod.TOTP


class MFAVerifyResponse(BaseModel):
	"""Response from MFA verification."""
	success: bool
	method: MFAMethod
	backup_codes_remaining: int | None = None
	message: str | None = None


@dataclass
class MFAService:
	"""Service for managing multi-factor authentication."""

	totp_manager: TOTPManager = field(default_factory=lambda: default_totp_manager)
	backup_manager: BackupCodeManager = field(default_factory=lambda: default_backup_manager)

	# In production, these would be database operations
	# Here we define the interface that the db layer should implement
	async def get_enrollment(
		self,
		user_id: uuid.UUID,
		method: MFAMethod = MFAMethod.TOTP,
	) -> MFAEnrollment | None:
		"""Get user's MFA enrollment (to be implemented by db layer)."""
		raise NotImplementedError("Implement in db layer")

	async def save_enrollment(self, enrollment: MFAEnrollment) -> None:
		"""Save MFA enrollment (to be implemented by db layer)."""
		raise NotImplementedError("Implement in db layer")

	async def get_decrypted_secret(self, enrollment: MFAEnrollment) -> str:
		"""Decrypt TOTP secret (to be implemented by db layer)."""
		raise NotImplementedError("Implement in db layer")

	def initiate_totp_setup(self, user_email: str) -> tuple[TOTPSetup, str]:
		"""Initiate TOTP setup for a user.

		Args:
			user_email: User's email address

		Returns:
			Tuple of (TOTPSetup, plain_secret)
		"""
		setup = self.totp_manager.setup_totp(user_email)
		return setup, setup.secret

	def generate_backup_codes(self) -> tuple[list[str], list[str]]:
		"""Generate backup codes.

		Returns:
			Tuple of (plain_codes, hashed_codes)
		"""
		return self.backup_manager.generate_codes()

	def verify_totp(
		self,
		secret: str,
		code: str,
		valid_window: int = 1,
	) -> bool:
		"""Verify a TOTP code.

		Args:
			secret: Plain TOTP secret
			code: Code to verify
			valid_window: Valid time windows

		Returns:
			True if valid
		"""
		return self.totp_manager.verify_code(secret, code, valid_window)

	def verify_backup_code(
		self,
		code: str,
		stored_hashes: list[str],
		used_indices: list[int],
	) -> tuple[bool, int | None]:
		"""Verify a backup code.

		Args:
			code: Backup code to verify
			stored_hashes: Stored code hashes
			used_indices: Already used code indices

		Returns:
			Tuple of (is_valid, code_index)
		"""
		return self.backup_manager.verify_and_consume(
			code,
			stored_hashes,
			set(used_indices),
		)

	def get_remaining_backup_codes(
		self,
		total_codes: int,
		used_indices: list[int],
	) -> int:
		"""Get count of remaining backup codes."""
		return self.backup_manager.count_remaining(
			total_codes,
			set(used_indices),
		)


# Default service instance
default_mfa_service = MFAService()
