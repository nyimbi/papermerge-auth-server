# (c) Copyright Datacraft, 2026
"""WebAuthn/Passkey API endpoints."""
import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from auth_server import schema
from auth_server.services.passkey import PasskeyService
from auth_server.db.engine import get_db
from auth_server.config import get_settings
from auth_server.utils import get_current_user_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/passkeys", tags=["Passkeys"])
settings = get_settings()


def get_passkey_service(db: Session = Depends(get_db)) -> PasskeyService:
	"""Get PasskeyService with configuration."""
	return PasskeyService(
		db=db,
		rp_id=settings.webauthn_rp_id,
		rp_name=settings.webauthn_rp_name,
		origin=settings.webauthn_origin,
		timeout=settings.webauthn_timeout,
	)


@router.post("/register/start", response_model=schema.PasskeyRegistrationStartResponse)
async def start_registration(
	request: schema.PasskeyRegistrationStartRequest,
	service: PasskeyService = Depends(get_passkey_service),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.PasskeyRegistrationStartResponse:
	"""Start passkey registration."""
	try:
		options = await service.start_registration(user_id, request.device_name)
		return schema.PasskeyRegistrationStartResponse(
			challenge=options.challenge,
			rp_id=options.rp_id,
			rp_name=options.rp_name,
			user_id=options.user_id,
			user_name=options.user_name,
			user_display_name=options.user_display_name,
			timeout=options.timeout,
			attestation=options.attestation,
			authenticator_selection=options.authenticator_selection,
			exclude_credentials=options.exclude_credentials,
		)
	except ValueError as e:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=str(e),
		)


@router.post("/register/complete", response_model=schema.PasskeyResponse)
async def complete_registration(
	request: schema.PasskeyRegistrationCompleteRequest,
	service: PasskeyService = Depends(get_passkey_service),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.PasskeyResponse:
	"""Complete passkey registration."""
	result = await service.complete_registration(
		request.challenge,
		request.credential,
	)

	if not result.success:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=result.message,
		)

	return schema.PasskeyResponse(
		success=True,
		credential_id=str(result.credential_id) if result.credential_id else None,
	)


@router.post("/authenticate/start", response_model=schema.PasskeyAuthenticationStartResponse)
async def start_authentication(
	request: schema.PasskeyAuthenticationStartRequest,
	service: PasskeyService = Depends(get_passkey_service),
) -> schema.PasskeyAuthenticationStartResponse:
	"""Start passkey authentication (no auth required)."""
	options = await service.start_authentication(request.username)
	return schema.PasskeyAuthenticationStartResponse(
		challenge=options.challenge,
		rp_id=options.rp_id,
		timeout=options.timeout,
		allow_credentials=options.allow_credentials,
		user_verification=options.user_verification,
	)


@router.post("/authenticate/complete", response_model=schema.PasskeyResponse)
async def complete_authentication(
	request: schema.PasskeyAuthenticationCompleteRequest,
	service: PasskeyService = Depends(get_passkey_service),
) -> schema.PasskeyResponse:
	"""Complete passkey authentication (no auth required)."""
	result = await service.complete_authentication(
		request.challenge,
		request.credential,
	)

	if not result.success:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=result.message,
		)

	return schema.PasskeyResponse(
		success=True,
		credential_id=str(result.credential_id) if result.credential_id else None,
	)


@router.get("/", response_model=schema.PasskeyListResponse)
async def list_passkeys(
	service: PasskeyService = Depends(get_passkey_service),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.PasskeyListResponse:
	"""List user's registered passkeys."""
	credentials = await service.list_credentials(user_id)
	return schema.PasskeyListResponse(
		credentials=[
			schema.PasskeyCredentialInfo(**cred) for cred in credentials
		]
	)


@router.delete("/{credential_id}", response_model=schema.PasskeyResponse)
async def revoke_passkey(
	credential_id: UUID,
	service: PasskeyService = Depends(get_passkey_service),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.PasskeyResponse:
	"""Revoke a passkey."""
	success = await service.revoke_credential(user_id, credential_id)

	if not success:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail="Passkey not found",
		)

	return schema.PasskeyResponse(success=True, message="Passkey revoked")
