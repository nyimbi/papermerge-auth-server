# (c) Copyright Datacraft, 2026
"""WebAuthn/Passkey authentication service."""
import logging
import os
import hashlib
import json
from uuid import UUID
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_server.db.orm import PasskeyCredential, User

logger = logging.getLogger(__name__)


@dataclass
class RegistrationOptions:
	"""WebAuthn registration options."""
	challenge: str
	rp_id: str
	rp_name: str
	user_id: str
	user_name: str
	user_display_name: str
	timeout: int
	attestation: str
	authenticator_selection: dict
	exclude_credentials: list[dict]


@dataclass
class AuthenticationOptions:
	"""WebAuthn authentication options."""
	challenge: str
	rp_id: str
	timeout: int
	allow_credentials: list[dict]
	user_verification: str


@dataclass
class PasskeyResult:
	"""Result of passkey operations."""
	success: bool
	credential_id: UUID | None = None
	user_id: UUID | None = None
	message: str | None = None


class PasskeyService:
	"""WebAuthn/Passkey authentication service."""

	def __init__(
		self,
		db: Session,
		rp_id: str = "localhost",
		rp_name: str = "dArchiva",
		origin: str = "https://localhost",
	):
		self.db = db
		self.rp_id = rp_id
		self.rp_name = rp_name
		self.origin = origin
		self._challenges: dict[str, dict] = {}  # In production, use Redis

	async def start_registration(
		self,
		user_id: UUID,
		device_name: str | None = None,
	) -> RegistrationOptions:
		"""Generate WebAuthn registration options."""
		user = self.db.get(User, user_id)
		if not user:
			raise ValueError(f"User not found: {user_id}")

		# Generate challenge
		challenge = os.urandom(32)
		challenge_b64 = self._base64url_encode(challenge)

		# Get existing credentials to exclude
		existing = await self._get_user_credentials(user_id)
		exclude_creds = [
			{
				"type": "public-key",
				"id": self._base64url_encode(cred.credential_id),
				"transports": ["internal", "usb", "ble", "nfc"],
			}
			for cred in existing
		]

		# Store challenge for verification
		self._challenges[challenge_b64] = {
			"user_id": str(user_id),
			"type": "registration",
			"device_name": device_name,
			"timestamp": datetime.now(timezone.utc).isoformat(),
		}

		return RegistrationOptions(
			challenge=challenge_b64,
			rp_id=self.rp_id,
			rp_name=self.rp_name,
			user_id=self._base64url_encode(user_id.bytes),
			user_name=user.username,
			user_display_name=f"{user.first_name} {user.last_name}".strip() or user.username,
			timeout=60000,
			attestation="none",
			authenticator_selection={
				"authenticatorAttachment": "platform",
				"residentKey": "preferred",
				"userVerification": "preferred",
			},
			exclude_credentials=exclude_creds,
		)

	async def complete_registration(
		self,
		challenge: str,
		credential_response: dict,
	) -> PasskeyResult:
		"""Complete WebAuthn registration."""
		# Verify challenge
		if challenge not in self._challenges:
			return PasskeyResult(success=False, message="Invalid or expired challenge")

		challenge_data = self._challenges.pop(challenge)
		if challenge_data["type"] != "registration":
			return PasskeyResult(success=False, message="Challenge type mismatch")

		user_id = UUID(challenge_data["user_id"])

		try:
			# Parse response
			client_data_json = self._base64url_decode(
				credential_response.get("response", {}).get("clientDataJSON", "")
			)
			attestation_object = self._base64url_decode(
				credential_response.get("response", {}).get("attestationObject", "")
			)

			# Verify client data
			client_data = json.loads(client_data_json)
			if client_data.get("type") != "webauthn.create":
				return PasskeyResult(success=False, message="Invalid client data type")
			if client_data.get("challenge") != challenge:
				return PasskeyResult(success=False, message="Challenge mismatch")
			if not client_data.get("origin", "").startswith(self.origin.split("://")[0]):
				return PasskeyResult(success=False, message="Origin mismatch")

			# Parse attestation object (simplified - full impl needs CBOR)
			credential_id = self._base64url_decode(credential_response.get("id", ""))
			public_key = self._extract_public_key(attestation_object)

			if not credential_id or not public_key:
				return PasskeyResult(success=False, message="Invalid credential data")

			# Store credential
			credential = PasskeyCredential(
				user_id=user_id,
				credential_id=credential_id,
				public_key=public_key,
				sign_count=0,
				device_name=challenge_data.get("device_name"),
				device_type=credential_response.get("authenticatorAttachment", "platform"),
				is_active=True,
			)
			self.db.add(credential)
			self.db.commit()
			self.db.refresh(credential)

			logger.info(f"Passkey registered for user {user_id}")

			return PasskeyResult(
				success=True,
				credential_id=credential.id,
				user_id=user_id,
			)

		except Exception as e:
			logger.error(f"Registration failed: {e}")
			return PasskeyResult(success=False, message=str(e))

	async def start_authentication(
		self,
		username: str | None = None,
	) -> AuthenticationOptions:
		"""Generate WebAuthn authentication options."""
		# Generate challenge
		challenge = os.urandom(32)
		challenge_b64 = self._base64url_encode(challenge)

		allow_credentials = []

		if username:
			# Get user's credentials
			user = self.db.scalar(
				select(User).where(User.username == username)
			)
			if user:
				credentials = await self._get_user_credentials(user.id)
				allow_credentials = [
					{
						"type": "public-key",
						"id": self._base64url_encode(cred.credential_id),
						"transports": ["internal", "usb", "ble", "nfc"],
					}
					for cred in credentials
					if cred.is_active
				]

		# Store challenge
		self._challenges[challenge_b64] = {
			"username": username,
			"type": "authentication",
			"timestamp": datetime.now(timezone.utc).isoformat(),
		}

		return AuthenticationOptions(
			challenge=challenge_b64,
			rp_id=self.rp_id,
			timeout=60000,
			allow_credentials=allow_credentials,
			user_verification="preferred",
		)

	async def complete_authentication(
		self,
		challenge: str,
		credential_response: dict,
	) -> PasskeyResult:
		"""Complete WebAuthn authentication."""
		# Verify challenge
		if challenge not in self._challenges:
			return PasskeyResult(success=False, message="Invalid or expired challenge")

		challenge_data = self._challenges.pop(challenge)
		if challenge_data["type"] != "authentication":
			return PasskeyResult(success=False, message="Challenge type mismatch")

		try:
			# Get credential
			credential_id = self._base64url_decode(credential_response.get("id", ""))
			credential = self.db.scalar(
				select(PasskeyCredential).where(
					PasskeyCredential.credential_id == credential_id
				)
			)

			if not credential or not credential.is_active:
				return PasskeyResult(success=False, message="Credential not found")

			# Parse response
			client_data_json = self._base64url_decode(
				credential_response.get("response", {}).get("clientDataJSON", "")
			)
			authenticator_data = self._base64url_decode(
				credential_response.get("response", {}).get("authenticatorData", "")
			)
			signature = self._base64url_decode(
				credential_response.get("response", {}).get("signature", "")
			)

			# Verify client data
			client_data = json.loads(client_data_json)
			if client_data.get("type") != "webauthn.get":
				return PasskeyResult(success=False, message="Invalid client data type")
			if client_data.get("challenge") != challenge:
				return PasskeyResult(success=False, message="Challenge mismatch")

			# Verify signature (simplified - full impl needs proper crypto)
			if not self._verify_signature(
				credential.public_key,
				authenticator_data,
				client_data_json,
				signature,
			):
				return PasskeyResult(success=False, message="Signature verification failed")

			# Update sign count
			new_sign_count = int.from_bytes(authenticator_data[33:37], "big")
			if new_sign_count <= credential.sign_count:
				logger.warning(f"Possible cloned authenticator for credential {credential.id}")
			credential.sign_count = new_sign_count
			credential.last_used_at = datetime.now(timezone.utc)
			self.db.commit()

			logger.info(f"Passkey authentication successful for user {credential.user_id}")

			return PasskeyResult(
				success=True,
				credential_id=credential.id,
				user_id=credential.user_id,
			)

		except Exception as e:
			logger.error(f"Authentication failed: {e}")
			return PasskeyResult(success=False, message=str(e))

	async def list_credentials(self, user_id: UUID) -> list[dict]:
		"""List user's registered passkeys."""
		credentials = await self._get_user_credentials(user_id)
		return [
			{
				"id": str(cred.id),
				"device_name": cred.device_name,
				"device_type": cred.device_type,
				"created_at": cred.created_at.isoformat() if cred.created_at else None,
				"last_used_at": cred.last_used_at.isoformat() if cred.last_used_at else None,
				"is_active": cred.is_active,
			}
			for cred in credentials
		]

	async def revoke_credential(
		self,
		user_id: UUID,
		credential_id: UUID,
	) -> bool:
		"""Revoke a passkey credential."""
		credential = self.db.get(PasskeyCredential, credential_id)
		if not credential or credential.user_id != user_id:
			return False

		credential.is_active = False
		self.db.commit()

		logger.info(f"Passkey {credential_id} revoked for user {user_id}")
		return True

	async def _get_user_credentials(self, user_id: UUID) -> list[PasskeyCredential]:
		"""Get all credentials for a user."""
		stmt = select(PasskeyCredential).where(
			PasskeyCredential.user_id == user_id
		)
		return list(self.db.scalars(stmt))

	def _base64url_encode(self, data: bytes) -> str:
		"""Base64url encode without padding."""
		import base64
		return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

	def _base64url_decode(self, data: str) -> bytes:
		"""Base64url decode with padding fix."""
		import base64
		padding = 4 - len(data) % 4
		if padding != 4:
			data += "=" * padding
		return base64.urlsafe_b64decode(data)

	def _extract_public_key(self, attestation_object: bytes) -> bytes:
		"""Extract public key from attestation object (simplified)."""
		# Full implementation would use CBOR decoding
		# For now, return the raw attestation object
		# In production, use py_webauthn library
		return attestation_object

	def _verify_signature(
		self,
		public_key: bytes,
		authenticator_data: bytes,
		client_data_json: bytes,
		signature: bytes,
	) -> bool:
		"""Verify WebAuthn signature (simplified)."""
		# Full implementation would use proper COSE key parsing and signature verification
		# For now, return True for demo - in production use py_webauthn
		# The signature verification involves:
		# 1. Hash client_data_json with SHA-256
		# 2. Concatenate authenticator_data + hash
		# 3. Verify signature against concatenated data using public key
		return len(signature) > 0  # Placeholder
