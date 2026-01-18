# (c) Copyright Datacraft, 2026
"""TOTP (Time-based One-Time Password) implementation."""

import base64
import io
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import pyotp
import qrcode
from pydantic import BaseModel


@dataclass
class TOTPSetup:
	"""TOTP setup data for enabling 2FA."""
	secret: str
	provisioning_uri: str
	qr_code_base64: str


class TOTPVerification(BaseModel):
	"""TOTP verification request."""
	code: str


class TOTPManager:
	"""Manages TOTP operations."""

	def __init__(
		self,
		issuer_name: str = "dArchiva",
		digits: int = 6,
		interval: int = 30,
		algorithm: str = "sha1",
	):
		"""Initialize TOTP manager.

		Args:
			issuer_name: Name shown in authenticator apps
			digits: Number of digits in OTP code
			interval: Time interval for code validity (seconds)
			algorithm: Hash algorithm (sha1, sha256, sha512)
		"""
		self.issuer_name = issuer_name
		self.digits = digits
		self.interval = interval
		self.algorithm = algorithm

	def generate_secret(self) -> str:
		"""Generate a new random TOTP secret.

		Returns:
			Base32-encoded secret string
		"""
		# Generate 20 bytes of random data (160 bits)
		random_bytes = secrets.token_bytes(20)
		# Encode as base32 (standard for TOTP secrets)
		return base64.b32encode(random_bytes).decode("utf-8").rstrip("=")

	def get_totp(self, secret: str) -> pyotp.TOTP:
		"""Get TOTP instance for a secret.

		Args:
			secret: Base32-encoded secret

		Returns:
			pyotp.TOTP instance
		"""
		return pyotp.TOTP(
			secret,
			digits=self.digits,
			interval=self.interval,
			digest=self.algorithm,
		)

	def generate_provisioning_uri(
		self,
		secret: str,
		user_email: str,
	) -> str:
		"""Generate otpauth:// URI for authenticator apps.

		Args:
			secret: Base32-encoded secret
			user_email: User's email address

		Returns:
			otpauth:// URI string
		"""
		totp = self.get_totp(secret)
		return totp.provisioning_uri(
			name=user_email,
			issuer_name=self.issuer_name,
		)

	def generate_qr_code(
		self,
		provisioning_uri: str,
		box_size: int = 10,
		border: int = 4,
	) -> str:
		"""Generate QR code image as base64.

		Args:
			provisioning_uri: otpauth:// URI
			box_size: Size of each QR code box
			border: Border size in boxes

		Returns:
			Base64-encoded PNG image
		"""
		qr = qrcode.QRCode(
			version=1,
			error_correction=qrcode.constants.ERROR_CORRECT_L,
			box_size=box_size,
			border=border,
		)
		qr.add_data(provisioning_uri)
		qr.make(fit=True)

		img = qr.make_image(fill_color="black", back_color="white")

		buffer = io.BytesIO()
		img.save(buffer, format="PNG")
		buffer.seek(0)

		return base64.b64encode(buffer.read()).decode("utf-8")

	def setup_totp(self, user_email: str) -> TOTPSetup:
		"""Generate complete TOTP setup for a user.

		Args:
			user_email: User's email address

		Returns:
			TOTPSetup with secret, URI, and QR code
		"""
		secret = self.generate_secret()
		provisioning_uri = self.generate_provisioning_uri(secret, user_email)
		qr_code_base64 = self.generate_qr_code(provisioning_uri)

		return TOTPSetup(
			secret=secret,
			provisioning_uri=provisioning_uri,
			qr_code_base64=qr_code_base64,
		)

	def verify_code(
		self,
		secret: str,
		code: str,
		valid_window: int = 1,
	) -> bool:
		"""Verify a TOTP code.

		Args:
			secret: Base32-encoded secret
			code: 6-digit code to verify
			valid_window: Number of intervals to check before/after current

		Returns:
			True if code is valid
		"""
		# Clean the code (remove spaces, dashes)
		code = code.replace(" ", "").replace("-", "")

		if not code.isdigit() or len(code) != self.digits:
			return False

		totp = self.get_totp(secret)
		return totp.verify(code, valid_window=valid_window)

	def get_current_code(self, secret: str) -> str:
		"""Get the current TOTP code (for testing).

		Args:
			secret: Base32-encoded secret

		Returns:
			Current 6-digit code
		"""
		totp = self.get_totp(secret)
		return totp.now()

	def get_time_remaining(self) -> int:
		"""Get seconds remaining in current TOTP interval.

		Returns:
			Seconds until next code
		"""
		now = datetime.now(timezone.utc).timestamp()
		return self.interval - int(now % self.interval)


# Default manager instance
default_totp_manager = TOTPManager()
