# (c) Copyright Datacraft, 2026
"""TOTP-based two-factor authentication service."""
import logging
import os
import base64
import hashlib
import hmac
import struct
import time
from uuid import UUID
from datetime import datetime, timezone
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session
from passlib.hash import pbkdf2_sha256

from auth_server.db.orm import TwoFactorAuth, User

logger = logging.getLogger(__name__)


@dataclass
class TOTPSetupResult:
	"""Result of TOTP setup."""
	success: bool
	secret_key: str | None = None
	provisioning_uri: str | None = None
	backup_codes: list[str] | None = None
	message: str | None = None


@dataclass
class TOTPVerifyResult:
	"""Result of TOTP verification."""
	success: bool
	message: str | None = None
	used_backup_code: bool = False


class TOTPService:
	"""TOTP two-factor authentication service."""

	def __init__(self, db: Session, issuer: str = "dArchiva"):
		self.db = db
		self.issuer = issuer
		self.digits = 6
		self.period = 30
		self.algorithm = "SHA1"

	async def setup_totp(self, user_id: UUID) -> TOTPSetupResult:
		"""Initialize TOTP for a user."""
		# Check if already set up
		existing = await self._get_totp_config(user_id)
		if existing and existing.is_enabled:
			return TOTPSetupResult(
				success=False,
				message="2FA is already enabled",
			)

		# Generate secret key (160 bits for SHA1)
		secret_bytes = os.urandom(20)
		secret_key = base64.b32encode(secret_bytes).decode("utf-8").rstrip("=")

		# Generate backup codes
		backup_codes = self._generate_backup_codes(10)
		hashed_codes = [pbkdf2_sha256.hash(code) for code in backup_codes]

		# Get user for provisioning URI
		user = self.db.get(User, user_id)
		if not user:
			return TOTPSetupResult(success=False, message="User not found")

		# Create or update TOTP config
		if existing:
			existing.secret_key = secret_key
			existing.backup_codes = hashed_codes
			existing.is_verified = False
			existing.is_enabled = False
		else:
			totp_config = TwoFactorAuth(
				user_id=user_id,
				secret_key=secret_key,
				backup_codes=hashed_codes,
				is_enabled=False,
				is_verified=False,
			)
			self.db.add(totp_config)

		self.db.commit()

		# Generate provisioning URI
		uri = self._generate_provisioning_uri(secret_key, user.email)

		logger.info(f"TOTP setup initiated for user {user_id}")

		return TOTPSetupResult(
			success=True,
			secret_key=secret_key,
			provisioning_uri=uri,
			backup_codes=backup_codes,
		)

	async def verify_and_enable(
		self,
		user_id: UUID,
		code: str,
	) -> TOTPVerifyResult:
		"""Verify TOTP code and enable 2FA."""
		config = await self._get_totp_config(user_id)
		if not config:
			return TOTPVerifyResult(success=False, message="TOTP not set up")

		if config.is_enabled:
			return TOTPVerifyResult(success=False, message="2FA already enabled")

		if not self._verify_code(config.secret_key, code):
			return TOTPVerifyResult(success=False, message="Invalid code")

		# Enable 2FA
		config.is_enabled = True
		config.is_verified = True
		config.verified_at = datetime.now(timezone.utc)
		self.db.commit()

		logger.info(f"2FA enabled for user {user_id}")

		return TOTPVerifyResult(success=True, message="2FA enabled successfully")

	async def verify_code(
		self,
		user_id: UUID,
		code: str,
	) -> TOTPVerifyResult:
		"""Verify a TOTP code during login."""
		config = await self._get_totp_config(user_id)
		if not config or not config.is_enabled:
			return TOTPVerifyResult(success=False, message="2FA not enabled")

		# Try TOTP code first
		if self._verify_code(config.secret_key, code):
			config.last_used_at = datetime.now(timezone.utc)
			self.db.commit()
			return TOTPVerifyResult(success=True)

		# Try backup codes
		if config.backup_codes:
			for idx, hashed_code in enumerate(config.backup_codes):
				if pbkdf2_sha256.verify(code, hashed_code):
					# Remove used backup code
					config.backup_codes = [
						c for i, c in enumerate(config.backup_codes) if i != idx
					]
					config.last_used_at = datetime.now(timezone.utc)
					self.db.commit()

					logger.warning(f"Backup code used for user {user_id}")

					return TOTPVerifyResult(
						success=True,
						used_backup_code=True,
						message=f"Backup code used. {len(config.backup_codes)} remaining.",
					)

		return TOTPVerifyResult(success=False, message="Invalid code")

	async def disable_totp(self, user_id: UUID, code: str) -> TOTPVerifyResult:
		"""Disable 2FA for a user (requires valid code)."""
		config = await self._get_totp_config(user_id)
		if not config or not config.is_enabled:
			return TOTPVerifyResult(success=False, message="2FA not enabled")

		# Verify code before disabling
		if not self._verify_code(config.secret_key, code):
			return TOTPVerifyResult(success=False, message="Invalid code")

		config.is_enabled = False
		self.db.commit()

		logger.info(f"2FA disabled for user {user_id}")

		return TOTPVerifyResult(success=True, message="2FA disabled")

	async def regenerate_backup_codes(
		self,
		user_id: UUID,
		code: str,
	) -> TOTPSetupResult:
		"""Regenerate backup codes (requires valid TOTP code)."""
		config = await self._get_totp_config(user_id)
		if not config or not config.is_enabled:
			return TOTPSetupResult(success=False, message="2FA not enabled")

		if not self._verify_code(config.secret_key, code):
			return TOTPSetupResult(success=False, message="Invalid code")

		# Generate new backup codes
		backup_codes = self._generate_backup_codes(10)
		config.backup_codes = [pbkdf2_sha256.hash(code) for code in backup_codes]
		self.db.commit()

		logger.info(f"Backup codes regenerated for user {user_id}")

		return TOTPSetupResult(
			success=True,
			backup_codes=backup_codes,
		)

	async def is_enabled(self, user_id: UUID) -> bool:
		"""Check if 2FA is enabled for a user."""
		config = await self._get_totp_config(user_id)
		return config is not None and config.is_enabled

	def _verify_code(self, secret_key: str, code: str, window: int = 1) -> bool:
		"""Verify a TOTP code with time window."""
		if len(code) != self.digits:
			return False

		current_time = int(time.time())

		# Check current and adjacent time windows
		for offset in range(-window, window + 1):
			expected = self._generate_totp(
				secret_key,
				current_time + (offset * self.period),
			)
			if hmac.compare_digest(code, expected):
				return True

		return False

	def _generate_totp(self, secret_key: str, timestamp: int | None = None) -> str:
		"""Generate a TOTP code."""
		if timestamp is None:
			timestamp = int(time.time())

		# Decode secret
		secret = base64.b32decode(secret_key + "=" * ((8 - len(secret_key) % 8) % 8))

		# Calculate counter
		counter = timestamp // self.period

		# Generate HMAC
		counter_bytes = struct.pack(">Q", counter)
		hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha1).digest()

		# Dynamic truncation
		offset = hmac_hash[-1] & 0x0F
		code_int = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
		code = str(code_int % (10 ** self.digits)).zfill(self.digits)

		return code

	def _generate_provisioning_uri(self, secret: str, account: str) -> str:
		"""Generate otpauth:// URI for authenticator apps."""
		import urllib.parse

		params = {
			"secret": secret,
			"issuer": self.issuer,
			"algorithm": self.algorithm,
			"digits": str(self.digits),
			"period": str(self.period),
		}
		query = urllib.parse.urlencode(params)
		label = urllib.parse.quote(f"{self.issuer}:{account}")

		return f"otpauth://totp/{label}?{query}"

	def _generate_backup_codes(self, count: int = 10) -> list[str]:
		"""Generate random backup codes."""
		codes = []
		for _ in range(count):
			# 8-digit codes grouped in pairs for readability
			code = "".join(str(os.urandom(1)[0] % 10) for _ in range(8))
			codes.append(f"{code[:4]}-{code[4:]}")
		return codes

	async def _get_totp_config(self, user_id: UUID) -> TwoFactorAuth | None:
		"""Get TOTP configuration for a user."""
		stmt = select(TwoFactorAuth).where(TwoFactorAuth.user_id == user_id)
		return self.db.scalar(stmt)
