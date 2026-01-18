# (c) Copyright Datacraft, 2026
"""TOTP (2FA) API endpoints."""
import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from auth_server import schema
from auth_server.services.totp import TOTPService
from auth_server.db.engine import get_db
from auth_server.utils import get_current_user_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/2fa/totp", tags=["2FA"])


@router.post("/setup", response_model=schema.TOTPSetupResponse)
async def setup_totp(
	db: Session = Depends(get_db),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.TOTPSetupResponse:
	"""Initialize TOTP 2FA for the current user."""
	service = TOTPService(db)
	result = await service.setup_totp(user_id)

	if not result.success:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=result.message,
		)

	return schema.TOTPSetupResponse(
		success=True,
		secret_key=result.secret_key,
		provisioning_uri=result.provisioning_uri,
		backup_codes=result.backup_codes,
	)


@router.post("/verify", response_model=schema.TOTPVerifyResponse)
async def verify_and_enable_totp(
	request: schema.TOTPVerifyRequest,
	db: Session = Depends(get_db),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.TOTPVerifyResponse:
	"""Verify TOTP code and enable 2FA."""
	service = TOTPService(db)
	result = await service.verify_and_enable(user_id, request.code)

	if not result.success:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=result.message,
		)

	return schema.TOTPVerifyResponse(
		success=True,
		message=result.message,
	)


@router.post("/disable", response_model=schema.TOTPVerifyResponse)
async def disable_totp(
	request: schema.TOTPDisableRequest,
	db: Session = Depends(get_db),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.TOTPVerifyResponse:
	"""Disable TOTP 2FA (requires valid code)."""
	service = TOTPService(db)
	result = await service.disable_totp(user_id, request.code)

	if not result.success:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=result.message,
		)

	return schema.TOTPVerifyResponse(
		success=True,
		message=result.message,
	)


@router.get("/status", response_model=schema.TOTPStatusResponse)
async def get_totp_status(
	db: Session = Depends(get_db),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.TOTPStatusResponse:
	"""Get TOTP 2FA status for current user."""
	service = TOTPService(db)
	enabled = await service.is_enabled(user_id)

	# Get backup codes count if enabled
	backup_count = None
	if enabled:
		config = await service._get_totp_config(user_id)
		if config and config.backup_codes:
			backup_count = len(config.backup_codes)

	return schema.TOTPStatusResponse(
		enabled=enabled,
		backup_codes_remaining=backup_count,
	)


@router.post("/backup-codes/regenerate", response_model=schema.TOTPSetupResponse)
async def regenerate_backup_codes(
	request: schema.TOTPVerifyRequest,
	db: Session = Depends(get_db),
	user_id: UUID = Depends(get_current_user_id),
) -> schema.TOTPSetupResponse:
	"""Regenerate backup codes (requires valid TOTP code)."""
	service = TOTPService(db)
	result = await service.regenerate_backup_codes(user_id, request.code)

	if not result.success:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=result.message,
		)

	return schema.TOTPSetupResponse(
		success=True,
		backup_codes=result.backup_codes,
	)
