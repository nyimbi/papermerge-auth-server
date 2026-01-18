# (c) Copyright Datacraft, 2026
"""WebAuthn API router for passkey authentication."""

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from .service import (
	AuthenticationOptions,
	RegistrationOptions,
	WebAuthnCredential,
	default_webauthn_service,
)

router = APIRouter(prefix="/webauthn", tags=["WebAuthn"])


# Request/Response models
class PasskeyListResponse(BaseModel):
	"""List of user's passkeys."""
	passkeys: list[WebAuthnCredential]


class RegisterBeginRequest(BaseModel):
	"""Request to begin passkey registration."""
	passkey_name: str | None = None


class RegisterBeginResponse(BaseModel):
	"""Response with registration options."""
	options: RegistrationOptions


class RegisterCompleteRequest(BaseModel):
	"""Request to complete passkey registration."""
	challenge: str
	credential: dict[str, Any]
	passkey_name: str | None = None


class RegisterCompleteResponse(BaseModel):
	"""Response after successful registration."""
	success: bool
	passkey_id: str
	passkey_name: str


class AuthenticateBeginRequest(BaseModel):
	"""Request to begin passkey authentication."""
	username: str | None = None


class AuthenticateBeginResponse(BaseModel):
	"""Response with authentication options."""
	options: AuthenticationOptions


class AuthenticateCompleteRequest(BaseModel):
	"""Request to complete passkey authentication."""
	challenge: str
	credential: dict[str, Any]


class AuthenticateCompleteResponse(BaseModel):
	"""Response after successful authentication."""
	success: bool
	user_id: str
	access_token: str | None = None


class PasskeyUpdateRequest(BaseModel):
	"""Request to update passkey name."""
	name: str


# In-memory credential storage (in production, use database)
_credentials: dict[str, list[WebAuthnCredential]] = {}
_challenges: dict[str, dict] = {}


async def get_current_user_id() -> uuid.UUID:
	"""Get current user ID (placeholder for auth dependency)."""
	# In production, this would be injected from auth middleware
	return uuid.uuid4()


@router.get("/passkeys", response_model=PasskeyListResponse)
async def list_passkeys(
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""List all passkeys for the authenticated user."""
	user_id = str(uuid.uuid4())  # Placeholder
	credentials = _credentials.get(user_id, [])

	# Don't expose public keys in list
	safe_creds = []
	for cred in credentials:
		safe_cred = cred.model_copy()
		safe_cred.public_key = "***"
		safe_creds.append(safe_cred)

	return PasskeyListResponse(passkeys=safe_creds)


@router.post("/register/begin", response_model=RegisterBeginResponse)
async def register_passkey_begin(
	request: RegisterBeginRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Begin passkey registration."""
	user_id = uuid.uuid4()  # Placeholder
	user_email = "user@example.com"  # Placeholder

	existing_creds = _credentials.get(str(user_id), [])

	options, challenge = default_webauthn_service.generate_registration_options(
		user_id=user_id,
		user_name=user_email,
		user_display_name=user_email.split("@")[0],
		existing_credentials=existing_creds,
	)

	# Store challenge with passkey name
	_challenges[challenge] = {
		"user_id": str(user_id),
		"type": "registration",
		"passkey_name": request.passkey_name or "Passkey",
	}

	return RegisterBeginResponse(options=options)


@router.post("/register/complete", response_model=RegisterCompleteResponse)
async def register_passkey_complete(
	request: RegisterCompleteRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Complete passkey registration."""
	challenge_data = _challenges.get(request.challenge)
	if not challenge_data or challenge_data["type"] != "registration":
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="Invalid or expired challenge",
		)

	credential = default_webauthn_service.verify_registration(
		challenge=request.challenge,
		credential_response=request.credential,
	)

	if not credential:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="Registration verification failed",
		)

	# Set passkey name
	credential.name = request.passkey_name or challenge_data.get("passkey_name", "Passkey")

	# Store credential
	user_id = challenge_data["user_id"]
	if user_id not in _credentials:
		_credentials[user_id] = []
	_credentials[user_id].append(credential)

	# Clean up challenge
	del _challenges[request.challenge]

	return RegisterCompleteResponse(
		success=True,
		passkey_id=credential.id,
		passkey_name=credential.name,
	)


@router.post("/authenticate/begin", response_model=AuthenticateBeginResponse)
async def authenticate_passkey_begin(
	request: AuthenticateBeginRequest,
):
	"""Begin passkey authentication."""
	# In production, look up user's credentials by username
	# For discoverable credentials (passkeys), we can allow empty credentials list

	# Get all credentials for the user (or empty for discoverable)
	credentials: list[WebAuthnCredential] = []

	if request.username:
		# Look up user's credentials
		# In production: fetch from database
		for user_creds in _credentials.values():
			credentials.extend(user_creds)

	options, challenge = default_webauthn_service.generate_authentication_options(
		credentials=credentials,
	)

	_challenges[challenge] = {
		"type": "authentication",
		"username": request.username,
	}

	return AuthenticateBeginResponse(options=options)


@router.post("/authenticate/complete", response_model=AuthenticateCompleteResponse)
async def authenticate_passkey_complete(
	request: AuthenticateCompleteRequest,
):
	"""Complete passkey authentication."""
	challenge_data = _challenges.get(request.challenge)
	if not challenge_data or challenge_data["type"] != "authentication":
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="Invalid or expired challenge",
		)

	# Find the credential by ID from the response
	credential_id = request.credential.get("id")
	stored_credential = None
	user_id = None

	for uid, creds in _credentials.items():
		for cred in creds:
			if cred.credential_id == credential_id:
				stored_credential = cred
				user_id = uid
				break
		if stored_credential:
			break

	if not stored_credential:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="Unknown credential",
		)

	success, new_sign_count = default_webauthn_service.verify_authentication(
		challenge=request.challenge,
		credential_response=request.credential,
		stored_credential=stored_credential,
	)

	if not success:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Authentication failed",
		)

	# Update sign count
	stored_credential.sign_count = new_sign_count
	stored_credential.last_used_at = datetime.now(timezone.utc)

	# Clean up challenge
	del _challenges[request.challenge]

	# In production, generate JWT token here
	return AuthenticateCompleteResponse(
		success=True,
		user_id=user_id,
		access_token=None,  # Would be JWT in production
	)


@router.patch("/passkeys/{passkey_id}")
async def update_passkey(
	passkey_id: str,
	request: PasskeyUpdateRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Update passkey name."""
	user_id = str(uuid.uuid4())  # Placeholder

	credentials = _credentials.get(user_id, [])
	for cred in credentials:
		if cred.id == passkey_id:
			cred.name = request.name
			return {"success": True, "name": request.name}

	raise HTTPException(
		status_code=status.HTTP_404_NOT_FOUND,
		detail="Passkey not found",
	)


@router.delete("/passkeys/{passkey_id}")
async def delete_passkey(
	passkey_id: str,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Delete a passkey."""
	user_id = str(uuid.uuid4())  # Placeholder

	credentials = _credentials.get(user_id, [])
	for i, cred in enumerate(credentials):
		if cred.id == passkey_id:
			del credentials[i]
			return {"success": True}

	raise HTTPException(
		status_code=status.HTTP_404_NOT_FOUND,
		detail="Passkey not found",
	)
