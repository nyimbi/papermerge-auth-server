# (c) Copyright Datacraft, 2026
"""WebAuthn/Passkey authentication service with proper verification."""
import logging
from uuid import UUID
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass

from sqlalchemy import select, delete
from sqlalchemy.orm import Session
from webauthn import (
	generate_registration_options,
	verify_registration_response,
	generate_authentication_options,
	verify_authentication_response,
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

from auth_server.db.orm import PasskeyCredential, User, WebAuthnChallenge

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
	access_token: str | None = None


class PasskeyService:
	"""WebAuthn/Passkey authentication service with database-backed storage."""

	CHALLENGE_EXPIRY_MINUTES = 5

	def __init__(
		self,
		db: Session,
		rp_id: str = "localhost",
		rp_name: str = "dArchiva",
		origin: str = "https://localhost",
		timeout: int = 60000,
	):
		self.db = db
		self.rp_id = rp_id
		self.rp_name = rp_name
		self.origin = origin
		self.timeout = timeout

	async def start_registration(
		self,
		user_id: UUID,
		device_name: str | None = None,
	) -> RegistrationOptions:
		"""Generate WebAuthn registration options."""
		user = self.db.get(User, user_id)
		if not user:
			raise ValueError(f"User not found: {user_id}")

		# Get existing credentials to exclude
		existing = await self._get_user_credentials(user_id)
		exclude_credentials = [
			PublicKeyCredentialDescriptor(
				id=cred.credential_id,
				type=PublicKeyCredentialType.PUBLIC_KEY,
				transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.USB],
			)
			for cred in existing
			if cred.is_active
		]

		# Generate registration options using py-webauthn
		options = generate_registration_options(
			rp_id=self.rp_id,
			rp_name=self.rp_name,
			user_id=str(user_id).encode(),
			user_name=user.username,
			user_display_name=f"{user.first_name} {user.last_name}".strip() or user.username,
			timeout=self.timeout,
			attestation="none",
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

		challenge_b64 = bytes_to_base64url(options.challenge)

		# Store challenge in database
		self._cleanup_expired_challenges()
		db_challenge = WebAuthnChallenge(
			challenge=challenge_b64,
			challenge_type="registration",
			user_id=user_id,
			device_name=device_name,
			expires_at=datetime.now(timezone.utc) + timedelta(minutes=self.CHALLENGE_EXPIRY_MINUTES),
		)
		self.db.add(db_challenge)
		self.db.commit()

		return RegistrationOptions(
			challenge=challenge_b64,
			rp_id=self.rp_id,
			rp_name=self.rp_name,
			user_id=bytes_to_base64url(str(user_id).encode()),
			user_name=user.username,
			user_display_name=f"{user.first_name} {user.last_name}".strip() or user.username,
			timeout=self.timeout,
			attestation="none",
			authenticator_selection={
				"authenticatorAttachment": "platform",
				"residentKey": "preferred",
				"userVerification": "preferred",
			},
			exclude_credentials=[
				{
					"type": "public-key",
					"id": bytes_to_base64url(cred.credential_id),
					"transports": ["internal", "usb"],
				}
				for cred in existing
				if cred.is_active
			],
		)

	async def complete_registration(
		self,
		challenge: str,
		credential_response: dict,
	) -> PasskeyResult:
		"""Complete WebAuthn registration with proper verification."""
		# Get and validate challenge from database
		db_challenge = self.db.scalar(
			select(WebAuthnChallenge).where(
				WebAuthnChallenge.challenge == challenge,
				WebAuthnChallenge.challenge_type == "registration",
				WebAuthnChallenge.used_at.is_(None),
				WebAuthnChallenge.expires_at > datetime.now(timezone.utc),
			)
		)

		if not db_challenge:
			return PasskeyResult(success=False, message="Invalid or expired challenge")

		user_id = db_challenge.user_id
		device_name = db_challenge.device_name

		try:
			# Verify the registration response using py-webauthn
			verification = verify_registration_response(
				credential=credential_response,
				expected_challenge=base64url_to_bytes(challenge),
				expected_rp_id=self.rp_id,
				expected_origin=self.origin,
				require_user_verification=False,
			)

			# Mark challenge as used
			db_challenge.used_at = datetime.now(timezone.utc)
			self.db.flush()

			# Store credential in database
			credential = PasskeyCredential(
				user_id=user_id,
				credential_id=verification.credential_id,
				public_key=verification.credential_public_key,
				sign_count=verification.sign_count,
				device_name=device_name,
				device_type=verification.credential_device_type or "platform",
				aaguid=verification.aaguid if verification.aaguid else None,
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
			self.db.rollback()
			return PasskeyResult(success=False, message=str(e))

	async def start_authentication(
		self,
		username: str | None = None,
	) -> AuthenticationOptions:
		"""Generate WebAuthn authentication options."""
		allow_credentials = []

		if username:
			# Get user's credentials
			user = self.db.scalar(
				select(User).where(User.username == username)
			)
			if user:
				credentials = await self._get_user_credentials(user.id)
				allow_credentials = [
					PublicKeyCredentialDescriptor(
						id=cred.credential_id,
						type=PublicKeyCredentialType.PUBLIC_KEY,
						transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.USB],
					)
					for cred in credentials
					if cred.is_active
				]

		# Generate authentication options using py-webauthn
		options = generate_authentication_options(
			rp_id=self.rp_id,
			timeout=self.timeout,
			allow_credentials=allow_credentials if allow_credentials else None,
			user_verification=UserVerificationRequirement.PREFERRED,
		)

		challenge_b64 = bytes_to_base64url(options.challenge)

		# Store challenge in database
		self._cleanup_expired_challenges()
		db_challenge = WebAuthnChallenge(
			challenge=challenge_b64,
			challenge_type="authentication",
			username=username,
			expires_at=datetime.now(timezone.utc) + timedelta(minutes=self.CHALLENGE_EXPIRY_MINUTES),
		)
		self.db.add(db_challenge)
		self.db.commit()

		return AuthenticationOptions(
			challenge=challenge_b64,
			rp_id=self.rp_id,
			timeout=self.timeout,
			allow_credentials=[
				{
					"type": "public-key",
					"id": bytes_to_base64url(cred.credential_id),
					"transports": ["internal", "usb"],
				}
				for cred in (await self._get_user_credentials(user.id) if username and user else [])
				if cred.is_active
			],
			user_verification="preferred",
		)

	async def complete_authentication(
		self,
		challenge: str,
		credential_response: dict,
	) -> PasskeyResult:
		"""Complete WebAuthn authentication with proper verification."""
		# Get and validate challenge from database
		db_challenge = self.db.scalar(
			select(WebAuthnChallenge).where(
				WebAuthnChallenge.challenge == challenge,
				WebAuthnChallenge.challenge_type == "authentication",
				WebAuthnChallenge.used_at.is_(None),
				WebAuthnChallenge.expires_at > datetime.now(timezone.utc),
			)
		)

		if not db_challenge:
			return PasskeyResult(success=False, message="Invalid or expired challenge")

		try:
			# Get credential from database by ID
			credential_id_b64 = credential_response.get("id", "")
			credential_id = base64url_to_bytes(credential_id_b64)

			credential = self.db.scalar(
				select(PasskeyCredential).where(
					PasskeyCredential.credential_id == credential_id
				)
			)

			if not credential or not credential.is_active:
				return PasskeyResult(success=False, message="Credential not found or inactive")

			# Verify the authentication response using py-webauthn
			verification = verify_authentication_response(
				credential=credential_response,
				expected_challenge=base64url_to_bytes(challenge),
				expected_rp_id=self.rp_id,
				expected_origin=self.origin,
				credential_public_key=credential.public_key,
				credential_current_sign_count=credential.sign_count,
				require_user_verification=False,
			)

			# Mark challenge as used
			db_challenge.used_at = datetime.now(timezone.utc)

			# Update credential sign count and last used
			credential.sign_count = verification.new_sign_count
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
			self.db.rollback()
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

	def _cleanup_expired_challenges(self) -> None:
		"""Remove expired challenges from database."""
		self.db.execute(
			delete(WebAuthnChallenge).where(
				WebAuthnChallenge.expires_at < datetime.now(timezone.utc)
			)
		)
		self.db.flush()
