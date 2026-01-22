# OIDC Router
# GitHub Issue #699: OIDC and Entra ID support
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from .models import (
	OIDCProvider, OIDCProviderPublic, OIDCProviderCreate, OIDCProviderUpdate,
	EntraIDProviderCreate, EntraIDConfig,
)
from .service import oidc_service, OIDCError, OIDCValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oidc", tags=["OIDC"])


class AuthorizeResponse(BaseModel):
	"""Authorization URL response."""
	authorization_url: str
	state: str


class CallbackRequest(BaseModel):
	"""Callback request from OIDC provider."""
	code: str
	state: str


class TokenResponse(BaseModel):
	"""Token response after successful authentication."""
	access_token: str
	token_type: str = "Bearer"
	expires_in: int | None = None
	refresh_token: str | None = None
	user: dict | None = None


class OIDCLoginUrl(BaseModel):
	"""OIDC login URL for frontend."""
	provider_id: str
	provider_name: str
	display_name: str
	login_url: str
	icon_url: str | None = None
	button_color: str | None = None


# --- Public Endpoints ---

@router.get("/providers", response_model=list[OIDCProviderPublic])
async def list_providers():
	"""List enabled OIDC providers (public info only)."""
	return oidc_service.get_enabled_providers()


@router.get("/login-options", response_model=list[OIDCLoginUrl])
async def get_login_options(
	request: Request,
	redirect_uri: str | None = Query(None, description="Post-login redirect URI"),
):
	"""Get login URLs for all enabled OIDC providers."""
	providers = oidc_service.get_enabled_providers()
	options = []

	# Determine callback URI
	base_url = str(request.base_url).rstrip("/")
	callback_uri = f"{base_url}/api/auth/oidc/callback"

	for provider_public in providers:
		provider = oidc_service.get_provider(provider_public.id)
		if not provider or not provider.authorization_endpoint:
			continue

		# Create authorization URL
		try:
			auth_url, auth_request = oidc_service.create_authorization_url(
				provider,
				redirect_uri=callback_uri,
				extra_params={"redirect_after": redirect_uri} if redirect_uri else None,
			)

			options.append(OIDCLoginUrl(
				provider_id=provider.id,
				provider_name=provider.name,
				display_name=provider.display_name or provider.name,
				login_url=auth_url,
				icon_url=provider.icon_url,
				button_color=provider.button_color,
			))
		except Exception as e:
			logger.warning(f"Failed to create auth URL for {provider.name}: {e}")

	return options


@router.get("/authorize/{provider_id}")
async def authorize(
	provider_id: str,
	request: Request,
	redirect_uri: str | None = Query(None),
) -> AuthorizeResponse:
	"""
	Initiate OIDC authorization flow.

	Returns authorization URL that the client should redirect to.
	"""
	provider = oidc_service.get_provider(provider_id)
	if not provider or not provider.enabled:
		raise HTTPException(status_code=404, detail="Provider not found or disabled")

	# Discover endpoints if needed
	if not provider.authorization_endpoint:
		try:
			await oidc_service.discover_endpoints(provider)
		except OIDCError as e:
			raise HTTPException(status_code=502, detail=str(e))

	# Determine callback URI
	base_url = str(request.base_url).rstrip("/")
	callback_uri = f"{base_url}/api/auth/oidc/callback"

	# Create authorization URL
	auth_url, auth_request = oidc_service.create_authorization_url(
		provider,
		redirect_uri=callback_uri,
		extra_params={"redirect_after": redirect_uri} if redirect_uri else None,
	)

	return AuthorizeResponse(
		authorization_url=auth_url,
		state=auth_request.state,
	)


@router.get("/authorize/{provider_id}/redirect")
async def authorize_redirect(
	provider_id: str,
	request: Request,
	redirect_uri: str | None = Query(None),
):
	"""Initiate OIDC flow with immediate redirect."""
	response = await authorize(provider_id, request, redirect_uri)
	return RedirectResponse(url=response.authorization_url, status_code=302)


@router.get("/callback")
async def callback(
	request: Request,
	code: str = Query(...),
	state: str = Query(...),
	error: str | None = Query(None),
	error_description: str | None = Query(None),
):
	"""
	OIDC callback endpoint.

	Exchanges authorization code for tokens and creates user session.
	"""
	# Handle provider errors
	if error:
		logger.warning(f"OIDC error: {error} - {error_description}")
		# Redirect to login page with error
		return RedirectResponse(
			url=f"/login?error=oidc&message={error_description or error}",
			status_code=302,
		)

	# Find provider from pending request
	# In production, state should be stored in Redis/DB with provider_id
	pending = oidc_service._pending_requests.get(state)
	if not pending:
		raise HTTPException(status_code=400, detail="Invalid or expired state")

	provider = oidc_service.get_provider(pending.provider_id)
	if not provider:
		raise HTTPException(status_code=400, detail="Provider not found")

	try:
		# Exchange code for tokens
		tokens = await oidc_service.exchange_code(provider, code, state)

		# Validate ID token
		claims = {}
		if tokens.id_token:
			claims = await oidc_service.validate_id_token(
				provider,
				tokens.id_token,
				nonce=pending.nonce,
			)

		# Get additional user info
		userinfo = {}
		if tokens.access_token and provider.userinfo_endpoint:
			userinfo = await oidc_service.get_userinfo(provider, tokens.access_token)

		# Extract user info
		user_info = oidc_service.extract_user_info(provider, claims, userinfo)

		# TODO: Create or update user in database
		# TODO: Create session token
		# For now, return the user info

		logger.info(f"OIDC login successful for user: {user_info.username}")

		# In production, create session and redirect
		# For now, redirect to home with success indicator
		return RedirectResponse(
			url=f"/?login=success&provider={provider.name}",
			status_code=302,
		)

	except OIDCValidationError as e:
		logger.warning(f"OIDC validation error: {e}")
		return RedirectResponse(
			url=f"/login?error=validation&message={str(e)}",
			status_code=302,
		)
	except OIDCError as e:
		logger.error(f"OIDC error: {e}")
		return RedirectResponse(
			url=f"/login?error=oidc&message={str(e)}",
			status_code=302,
		)


@router.post("/logout/{provider_id}")
async def logout(
	provider_id: str,
	id_token_hint: str | None = None,
	post_logout_redirect_uri: str | None = None,
):
	"""
	Initiate OIDC logout (single sign-out).

	Returns logout URL if provider supports it.
	"""
	provider = oidc_service.get_provider(provider_id)
	if not provider:
		raise HTTPException(status_code=404, detail="Provider not found")

	logout_url = oidc_service.create_logout_url(
		provider,
		id_token_hint=id_token_hint,
		post_logout_redirect_uri=post_logout_redirect_uri,
	)

	if logout_url:
		return {"logout_url": logout_url}
	return {"message": "Provider does not support single sign-out"}


# --- Admin Endpoints ---

@router.post("/providers", response_model=OIDCProviderPublic)
async def create_provider(data: OIDCProviderCreate):
	"""Create a new OIDC provider (admin only)."""
	# TODO: Add admin auth check

	provider = OIDCProvider(
		name=data.name,
		provider_type=data.provider_type,
		issuer=data.issuer,
		client_id=data.client_id,
		client_secret=data.client_secret,
		scopes=data.scopes or ["openid", "email", "profile"],
		auto_create_users=data.auto_create_users,
		display_name=data.display_name,
	)

	# Discover endpoints
	try:
		await oidc_service.discover_endpoints(provider)
	except OIDCError as e:
		raise HTTPException(status_code=400, detail=f"Discovery failed: {e}")

	oidc_service.register_provider(provider)
	return OIDCProviderPublic.from_provider(provider)


@router.post("/providers/entra-id", response_model=OIDCProviderPublic)
async def create_entra_id_provider(data: EntraIDProviderCreate):
	"""Create Microsoft Entra ID provider with simplified configuration."""
	# TODO: Add admin auth check

	config = EntraIDConfig(
		tenant_id=data.tenant_id,
		client_id=data.client_id,
		client_secret=data.client_secret,
	)

	provider = oidc_service.register_entra_id(config, data.name)

	if data.admin_groups:
		# Store admin groups mapping
		# TODO: Implement group-to-role mapping
		pass

	return OIDCProviderPublic.from_provider(provider)


@router.patch("/providers/{provider_id}", response_model=OIDCProviderPublic)
async def update_provider(provider_id: str, data: OIDCProviderUpdate):
	"""Update OIDC provider settings (admin only)."""
	# TODO: Add admin auth check

	provider = oidc_service.get_provider(provider_id)
	if not provider:
		raise HTTPException(status_code=404, detail="Provider not found")

	# Update fields
	if data.name is not None:
		provider.name = data.name
	if data.enabled is not None:
		provider.enabled = data.enabled
	if data.is_default is not None:
		# Clear other defaults first
		if data.is_default:
			for p in oidc_service._providers.values():
				p.is_default = False
		provider.is_default = data.is_default
	if data.client_secret is not None:
		provider.client_secret = data.client_secret
	if data.scopes is not None:
		provider.scopes = data.scopes
	if data.auto_create_users is not None:
		provider.auto_create_users = data.auto_create_users
	if data.auto_update_user_info is not None:
		provider.auto_update_user_info = data.auto_update_user_info
	if data.sync_groups is not None:
		provider.sync_groups = data.sync_groups
	if data.display_name is not None:
		provider.display_name = data.display_name

	provider.updated_at = __import__("datetime").datetime.utcnow()

	return OIDCProviderPublic.from_provider(provider)


@router.delete("/providers/{provider_id}")
async def delete_provider(provider_id: str):
	"""Delete OIDC provider (admin only)."""
	# TODO: Add admin auth check

	if provider_id not in oidc_service._providers:
		raise HTTPException(status_code=404, detail="Provider not found")

	del oidc_service._providers[provider_id]
	return {"message": "Provider deleted"}
