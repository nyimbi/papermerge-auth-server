# (c) Copyright Datacraft, 2026
"""WebAuthn service for passkey authentication."""

import base64
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel
from webauthn import (
	generate_authentication_options,
	generate_registration_options,
	verify_authentication_response,
	verify_registration_response,
)
from webauthn.helpers import (
	base64url_to_bytes,
	bytes_to_base64url,
)
from webauthn.helpers.structs import (
	AuthenticatorAttachment,
	AuthenticatorSelectionCriteria,
	AuthenticatorTransport,
	COSEAlgorithmIdentifier,
	PublicKeyCredentialDescriptor,
	PublicKeyCredentialType,
	ResidentKeyRequirement,
	UserVerificationRequirement,
)


class WebAuthnCredential(BaseModel):
	"""Stored WebAuthn credential."""
	id: str
	credential_id: str  # Base64URL encoded
	public_key: str  # Base64URL encoded
	sign_count: int
	transports: list[str] = []
	name: str = "Passkey"
	created_at: datetime
	last_used_at: datetime | None = None
	user_id: uuid.UUID
	aaguid: str | None = None
	device_type: str | None = None


class RegistrationOptions(BaseModel):
	"""Registration options for client."""
	challenge: str
	rp_id: str
	rp_name: str
	user_id: str
	user_name: str
	user_display_name: str
	timeout: int
	attestation: str
	authenticator_selection: dict[str, Any]
	pub_key_cred_params: list[dict[str, Any]]
	exclude_credentials: list[dict[str, Any]] = []


class AuthenticationOptions(BaseModel):
	"""Authentication options for client."""
	challenge: str
	rp_id: str
	timeout: int
	user_verification: str
	allow_credentials: list[dict[str, Any]] = []


@dataclass
class WebAuthnService:
	"""Service for WebAuthn/FIDO2 operations."""

	rp_id: str = "localhost"
	rp_name: str = "dArchiva"
	rp_origin: str = "http://localhost:3000"
	timeout: int = 60000  # 60 seconds

	# Challenge storage (in production, use Redis or database)
	_challenges: dict[str, dict] = field(default_factory=dict)

	def generate_registration_options(
		self,
		user_id: uuid.UUID,
		user_name: str,
		user_display_name: str,
		existing_credentials: list[WebAuthnCredential] | None = None,
	) -> tuple[RegistrationOptions, str]:
		"""Generate options for passkey registration.

		Args:
			user_id: User's UUID
			user_name: Username (email)
			user_display_name: Display name
			existing_credentials: Existing passkeys to exclude

		Returns:
			Tuple of (options, challenge)
		"""
		# Convert existing credentials to exclude list
		exclude_credentials = []
		if existing_credentials:
			for cred in existing_credentials:
				transports = [AuthenticatorTransport(t) for t in cred.transports]
				exclude_credentials.append(
					PublicKeyCredentialDescriptor(
						id=base64url_to_bytes(cred.credential_id),
						type=PublicKeyCredentialType.PUBLIC_KEY,
						transports=transports if transports else None,
					)
				)

		# Generate registration options
		options = generate_registration_options(
			rp_id=self.rp_id,
			rp_name=self.rp_name,
			user_id=str(user_id).encode(),
			user_name=user_name,
			user_display_name=user_display_name,
			timeout=self.timeout,
			attestation="none",  # Don't require attestation
			authenticator_selection=AuthenticatorSelectionCriteria(
				authenticator_attachment=AuthenticatorAttachment.PLATFORM,
				resident_key=ResidentKeyRequirement.PREFERRED,
				user_verification=UserVerificationRequirement.PREFERRED,
			),
			supported_pub_key_algs=[
				COSEAlgorithmIdentifier.ECDSA_SHA_256,
				COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
			],
			exclude_credentials=exclude_credentials if exclude_credentials else None,
		)

		challenge = bytes_to_base64url(options.challenge)

		# Store challenge for verification
		self._challenges[challenge] = {
			"user_id": str(user_id),
			"type": "registration",
			"created_at": datetime.now(timezone.utc),
		}

		# Convert to response format
		return RegistrationOptions(
			challenge=challenge,
			rp_id=self.rp_id,
			rp_name=self.rp_name,
			user_id=bytes_to_base64url(str(user_id).encode()),
			user_name=user_name,
			user_display_name=user_display_name,
			timeout=self.timeout,
			attestation="none",
			authenticator_selection={
				"authenticatorAttachment": "platform",
				"residentKey": "preferred",
				"userVerification": "preferred",
			},
			pub_key_cred_params=[
				{"type": "public-key", "alg": -7},  # ES256
				{"type": "public-key", "alg": -257},  # RS256
			],
			exclude_credentials=[
				{
					"id": cred.credential_id,
					"type": "public-key",
					"transports": cred.transports,
				}
				for cred in (existing_credentials or [])
			],
		), challenge

	def verify_registration(
		self,
		challenge: str,
		credential_response: dict[str, Any],
	) -> WebAuthnCredential | None:
		"""Verify registration response from authenticator.

		Args:
			challenge: Original challenge
			credential_response: Response from navigator.credentials.create()

		Returns:
			WebAuthnCredential if valid, None otherwise
		"""
		# Get stored challenge
		stored = self._challenges.get(challenge)
		if not stored or stored["type"] != "registration":
			return None

		try:
			# Verify the registration
			verification = verify_registration_response(
				credential=credential_response,
				expected_challenge=base64url_to_bytes(challenge),
				expected_rp_id=self.rp_id,
				expected_origin=self.rp_origin,
				require_user_verification=False,
			)

			# Clean up challenge
			del self._challenges[challenge]

			# Create credential record
			return WebAuthnCredential(
				id=str(uuid.uuid4()),
				credential_id=bytes_to_base64url(verification.credential_id),
				public_key=bytes_to_base64url(verification.credential_public_key),
				sign_count=verification.sign_count,
				transports=[],  # Would come from client response
				name="Passkey",
				created_at=datetime.now(timezone.utc),
				user_id=uuid.UUID(stored["user_id"]),
				aaguid=bytes_to_base64url(verification.aaguid) if verification.aaguid else None,
				device_type=verification.credential_device_type or None,
			)

		except Exception as e:
			# Log error in production
			print(f"Registration verification failed: {e}")
			return None

	def generate_authentication_options(
		self,
		credentials: list[WebAuthnCredential],
	) -> tuple[AuthenticationOptions, str]:
		"""Generate options for passkey authentication.

		Args:
			credentials: User's registered passkeys

		Returns:
			Tuple of (options, challenge)
		"""
		# Build allow credentials list
		allow_credentials = []
		for cred in credentials:
			transports = [AuthenticatorTransport(t) for t in cred.transports] if cred.transports else None
			allow_credentials.append(
				PublicKeyCredentialDescriptor(
					id=base64url_to_bytes(cred.credential_id),
					type=PublicKeyCredentialType.PUBLIC_KEY,
					transports=transports,
				)
			)

		# Generate authentication options
		options = generate_authentication_options(
			rp_id=self.rp_id,
			timeout=self.timeout,
			allow_credentials=allow_credentials if allow_credentials else None,
			user_verification=UserVerificationRequirement.PREFERRED,
		)

		challenge = bytes_to_base64url(options.challenge)

		# Store challenge
		self._challenges[challenge] = {
			"type": "authentication",
			"credentials": [c.credential_id for c in credentials],
			"created_at": datetime.now(timezone.utc),
		}

		return AuthenticationOptions(
			challenge=challenge,
			rp_id=self.rp_id,
			timeout=self.timeout,
			user_verification="preferred",
			allow_credentials=[
				{
					"id": cred.credential_id,
					"type": "public-key",
					"transports": cred.transports,
				}
				for cred in credentials
			],
		), challenge

	def verify_authentication(
		self,
		challenge: str,
		credential_response: dict[str, Any],
		stored_credential: WebAuthnCredential,
	) -> tuple[bool, int]:
		"""Verify authentication response.

		Args:
			challenge: Original challenge
			credential_response: Response from navigator.credentials.get()
			stored_credential: Stored credential to verify against

		Returns:
			Tuple of (success, new_sign_count)
		"""
		stored = self._challenges.get(challenge)
		if not stored or stored["type"] != "authentication":
			return False, 0

		try:
			verification = verify_authentication_response(
				credential=credential_response,
				expected_challenge=base64url_to_bytes(challenge),
				expected_rp_id=self.rp_id,
				expected_origin=self.rp_origin,
				credential_public_key=base64url_to_bytes(stored_credential.public_key),
				credential_current_sign_count=stored_credential.sign_count,
				require_user_verification=False,
			)

			# Clean up challenge
			del self._challenges[challenge]

			return True, verification.new_sign_count

		except Exception as e:
			print(f"Authentication verification failed: {e}")
			return False, 0


# Default service instance
default_webauthn_service = WebAuthnService()
