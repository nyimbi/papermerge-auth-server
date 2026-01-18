# (c) Copyright Datacraft, 2026
"""MFA-enabled login endpoints."""
import logging
import os
import hashlib
from uuid import UUID
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Response, Depends, status
from sqlalchemy.orm import Session

from auth_server import schema
from auth_server.auth import authenticate, create_token
from auth_server.services.totp import TOTPService
from auth_server.services.passkey import PasskeyService
from auth_server.db.engine import get_db
from auth_server.db.orm import LoginAttempt
from auth_server.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

# In-memory MFA session storage (use Redis in production)
_mfa_sessions: dict[str, dict] = {}


@router.post("/login", response_model=schema.MFALoginResponse)
async def mfa_login(
	response: Response,
	request: schema.MFALoginRequest,
	db: Session = Depends(get_db),
) -> schema.MFALoginResponse:
	"""Login with optional TOTP code."""
	# Authenticate with username/password
	user = authenticate(db, username=request.username, password=request.password)

	if user is None:
		# Log failed attempt
		await _log_attempt(db, request.username, False, "invalid_credentials")
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Invalid credentials",
		)

	# Check if user has 2FA enabled
	totp_service = TOTPService(db)
	has_totp = await totp_service.is_enabled(user.id)

	# Check for passkeys
	passkey_service = PasskeyService(db)
	passkeys = await passkey_service.list_credentials(user.id)
	has_passkeys = len([p for p in passkeys if p["is_active"]]) > 0

	if has_totp or has_passkeys:
		# If TOTP code provided, verify it
		if request.totp_code and has_totp:
			result = await totp_service.verify_code(user.id, request.totp_code)
			if result.success:
				# Log successful attempt
				await _log_attempt(db, request.username, True, mfa_method="totp")

				# Create token
				access_token = create_token(user)
				response.set_cookie("access_token", access_token)
				response.headers["Authorization"] = f"Bearer {access_token}"

				return schema.MFALoginResponse(
					access_token=access_token,
					requires_mfa=False,
				)
			else:
				await _log_attempt(db, request.username, False, "invalid_totp")
				raise HTTPException(
					status_code=status.HTTP_401_UNAUTHORIZED,
					detail="Invalid TOTP code",
				)

		# MFA required but not provided - create MFA session
		mfa_token = _create_mfa_session(user.id)
		mfa_methods = []
		if has_totp:
			mfa_methods.append("totp")
		if has_passkeys:
			mfa_methods.append("passkey")

		return schema.MFALoginResponse(
			requires_mfa=True,
			mfa_methods=mfa_methods,
			mfa_session_token=mfa_token,
		)

	# No MFA required - create token directly
	await _log_attempt(db, request.username, True)

	access_token = create_token(user)
	response.set_cookie("access_token", access_token)
	response.headers["Authorization"] = f"Bearer {access_token}"

	return schema.MFALoginResponse(
		access_token=access_token,
		requires_mfa=False,
	)


@router.post("/mfa/verify", response_model=schema.MFALoginResponse)
async def verify_mfa(
	response: Response,
	request: schema.MFAVerifyRequest,
	db: Session = Depends(get_db),
) -> schema.MFALoginResponse:
	"""Verify MFA code to complete login."""
	# Validate MFA session
	session = _validate_mfa_session(request.mfa_session_token)
	if not session:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Invalid or expired MFA session",
		)

	user_id = session["user_id"]

	if request.method == "totp":
		totp_service = TOTPService(db)
		result = await totp_service.verify_code(user_id, request.code)

		if not result.success:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail=result.message or "Invalid code",
			)

	elif request.method == "backup":
		totp_service = TOTPService(db)
		result = await totp_service.verify_code(user_id, request.code)

		if not result.success:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Invalid backup code",
			)

	else:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=f"Unknown MFA method: {request.method}",
		)

	# Clear MFA session
	_clear_mfa_session(request.mfa_session_token)

	# Get user and create token
	from auth_server.db import api as dbapi
	user = dbapi.get_user_uuid(db, user_id)

	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="User not found",
		)

	access_token = create_token(user)
	response.set_cookie("access_token", access_token)
	response.headers["Authorization"] = f"Bearer {access_token}"

	return schema.MFALoginResponse(
		access_token=access_token,
		requires_mfa=False,
	)


def _create_mfa_session(user_id: UUID, ttl_seconds: int = 300) -> str:
	"""Create an MFA session token."""
	token = hashlib.sha256(os.urandom(32)).hexdigest()
	expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

	_mfa_sessions[token] = {
		"user_id": user_id,
		"expires": expires,
	}

	return token


def _validate_mfa_session(token: str) -> dict | None:
	"""Validate an MFA session token."""
	session = _mfa_sessions.get(token)
	if not session:
		return None

	if datetime.now(timezone.utc) > session["expires"]:
		del _mfa_sessions[token]
		return None

	return session


def _clear_mfa_session(token: str) -> None:
	"""Clear an MFA session."""
	_mfa_sessions.pop(token, None)


async def _log_attempt(
	db: Session,
	username: str,
	success: bool,
	failure_reason: str | None = None,
	mfa_method: str | None = None,
) -> None:
	"""Log a login attempt."""
	attempt = LoginAttempt(
		username=username,
		ip_address="0.0.0.0",  # Would get from request in real impl
		success=success,
		failure_reason=failure_reason,
		mfa_method=mfa_method,
	)
	db.add(attempt)
	db.commit()
