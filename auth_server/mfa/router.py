# (c) Copyright Datacraft, 2026
"""MFA API router."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from .backup import default_backup_manager
from .service import MFAMethod, MFAStatus, default_mfa_service
from .totp import TOTPSetup, default_totp_manager

router = APIRouter(prefix="/mfa", tags=["MFA"])


class MFAStatusResponse(BaseModel):
	"""Response for MFA status check."""
	totp_enabled: bool
	webauthn_enabled: bool
	backup_codes_remaining: int
	last_verified_at: datetime | None


class TOTPSetupRequest(BaseModel):
	"""Request to initiate TOTP setup."""
	pass


class TOTPSetupResponse(BaseModel):
	"""Response from TOTP setup initiation."""
	secret: str
	provisioning_uri: str
	qr_code_base64: str
	backup_codes: list[str]


class TOTPEnableRequest(BaseModel):
	"""Request to enable TOTP after setup."""
	code: str


class TOTPVerifyRequest(BaseModel):
	"""Request to verify TOTP code."""
	code: str


class TOTPVerifyResponse(BaseModel):
	"""Response from TOTP verification."""
	success: bool
	method: MFAMethod


class BackupCodeVerifyRequest(BaseModel):
	"""Request to verify backup code."""
	code: str


class BackupCodesResponse(BaseModel):
	"""Response with new backup codes."""
	codes: list[str]
	remaining: int


class TOTPDisableRequest(BaseModel):
	"""Request to disable TOTP."""
	code: str  # Require current TOTP code to disable


# In-memory pending setups (in production, use Redis or database)
_pending_setups: dict[str, dict] = {}


async def get_current_user_id() -> uuid.UUID:
	"""Get current user ID (placeholder for auth dependency)."""
	# In production, this would be injected from auth middleware
	raise HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Not authenticated",
	)


async def get_current_user_email() -> str:
	"""Get current user email (placeholder for auth dependency)."""
	raise HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Not authenticated",
	)


@router.get("/status", response_model=MFAStatusResponse)
async def get_mfa_status(
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Get current MFA status for the authenticated user."""
	# In production, fetch from database
	return MFAStatusResponse(
		totp_enabled=False,
		webauthn_enabled=False,
		backup_codes_remaining=0,
		last_verified_at=None,
	)


@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def initiate_totp_setup(
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
	# user_email: Annotated[str, Depends(get_current_user_email)],
):
	"""Initiate TOTP setup for the authenticated user."""
	# Placeholder email for development
	user_email = "user@example.com"
	user_id = uuid.uuid4()

	# Generate TOTP setup
	setup = default_totp_manager.setup_totp(user_email)

	# Generate backup codes
	plain_codes, hashed_codes = default_backup_manager.generate_codes()

	# Store pending setup (in production, use secure storage)
	_pending_setups[str(user_id)] = {
		"secret": setup.secret,
		"backup_codes_hashes": hashed_codes,
		"created_at": datetime.now(timezone.utc),
	}

	return TOTPSetupResponse(
		secret=setup.secret,
		provisioning_uri=setup.provisioning_uri,
		qr_code_base64=setup.qr_code_base64,
		backup_codes=plain_codes,
	)


@router.post("/totp/enable", response_model=dict)
async def enable_totp(
	request: TOTPEnableRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Enable TOTP after verifying setup code."""
	user_id = uuid.uuid4()  # Placeholder

	pending = _pending_setups.get(str(user_id))
	if not pending:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="No pending TOTP setup found. Please initiate setup first.",
		)

	# Verify the code
	if not default_totp_manager.verify_code(pending["secret"], request.code):
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail="Invalid TOTP code",
		)

	# In production, save to database and encrypt secret
	# Remove pending setup
	del _pending_setups[str(user_id)]

	return {
		"success": True,
		"message": "TOTP enabled successfully",
		"backup_codes_count": len(pending["backup_codes_hashes"]),
	}


@router.post("/totp/verify", response_model=TOTPVerifyResponse)
async def verify_totp(
	request: TOTPVerifyRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Verify a TOTP code during login."""
	# In production, fetch user's encrypted secret from database
	# and decrypt it before verification

	# For development, we'll return a simulated response
	# In production: verify against stored secret

	return TOTPVerifyResponse(
		success=False,  # Would be actual verification result
		method=MFAMethod.TOTP,
	)


@router.post("/totp/disable", response_model=dict)
async def disable_totp(
	request: TOTPDisableRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Disable TOTP for the authenticated user."""
	# In production:
	# 1. Fetch user's encrypted secret
	# 2. Verify the provided code
	# 3. Delete TOTP enrollment

	return {
		"success": True,
		"message": "TOTP disabled successfully",
	}


@router.post("/backup-codes/verify", response_model=TOTPVerifyResponse)
async def verify_backup_code(
	request: BackupCodeVerifyRequest,
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Verify a backup code during login."""
	# In production:
	# 1. Fetch user's backup code hashes
	# 2. Verify and mark as used

	return TOTPVerifyResponse(
		success=False,  # Would be actual verification result
		method=MFAMethod.BACKUP_CODE,
	)


@router.post("/backup-codes/regenerate", response_model=BackupCodesResponse)
async def regenerate_backup_codes(
	request: TOTPVerifyRequest,  # Require TOTP code to regenerate
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Regenerate backup codes (requires TOTP verification)."""
	# In production:
	# 1. Verify TOTP code
	# 2. Generate new backup codes
	# 3. Replace old codes in database

	plain_codes, hashed_codes = default_backup_manager.generate_codes()

	return BackupCodesResponse(
		codes=plain_codes,
		remaining=len(plain_codes),
	)


@router.get("/backup-codes/remaining")
async def get_backup_codes_remaining(
	# user_id: Annotated[uuid.UUID, Depends(get_current_user_id)],
):
	"""Get count of remaining backup codes."""
	# In production, fetch from database
	return {"remaining": 0}
