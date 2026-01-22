# OIDC Service
# GitHub Issue #699: OIDC and Entra ID support
import secrets
import hashlib
import base64
import json
import logging
from datetime import datetime, timedelta
from urllib.parse import urlencode
from typing import Any

import httpx
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError

from .models import (
	OIDCProvider, OIDCAuthRequest, OIDCTokenResponse, OIDCUserInfo,
	OIDCProviderPublic, EntraIDConfig,
)

logger = logging.getLogger(__name__)


class OIDCError(Exception):
	"""Base OIDC error."""
	pass


class OIDCDiscoveryError(OIDCError):
	"""Failed to discover OIDC configuration."""
	pass


class OIDCTokenError(OIDCError):
	"""Token exchange failed."""
	pass


class OIDCValidationError(OIDCError):
	"""Token validation failed."""
	pass


class OIDCService:
	"""OIDC authentication service."""

	def __init__(self, providers: dict[str, OIDCProvider] | None = None):
		self._providers: dict[str, OIDCProvider] = providers or {}
		self._pending_requests: dict[str, OIDCAuthRequest] = {}
		self._jwks_cache: dict[str, tuple[datetime, dict]] = {}
		self._discovery_cache: dict[str, tuple[datetime, dict]] = {}

	def register_provider(self, provider: OIDCProvider) -> None:
		"""Register an OIDC provider."""
		self._providers[provider.id] = provider
		logger.info(f"Registered OIDC provider: {provider.name} ({provider.id})")

	def register_entra_id(self, config: EntraIDConfig, name: str = "Microsoft") -> OIDCProvider:
		"""Register Microsoft Entra ID provider."""
		provider = config.to_oidc_provider(name)
		self.register_provider(provider)
		return provider

	def get_provider(self, provider_id: str) -> OIDCProvider | None:
		"""Get provider by ID."""
		return self._providers.get(provider_id)

	def get_enabled_providers(self) -> list[OIDCProviderPublic]:
		"""Get list of enabled providers (public info only)."""
		return [
			OIDCProviderPublic.from_provider(p)
			for p in self._providers.values()
			if p.enabled
		]

	def get_default_provider(self) -> OIDCProvider | None:
		"""Get the default provider if one is set."""
		for provider in self._providers.values():
			if provider.enabled and provider.is_default:
				return provider
		return None

	async def discover_endpoints(self, provider: OIDCProvider) -> dict[str, Any]:
		"""Discover OIDC endpoints from well-known configuration."""
		cache_key = provider.issuer
		now = datetime.utcnow()

		# Check cache (1 hour TTL)
		if cache_key in self._discovery_cache:
			cached_at, config = self._discovery_cache[cache_key]
			if now - cached_at < timedelta(hours=1):
				return config

		discovery_url = f"{provider.issuer}/.well-known/openid-configuration"

		try:
			async with httpx.AsyncClient() as client:
				response = await client.get(discovery_url, timeout=10.0)
				response.raise_for_status()
				config = response.json()

				# Cache the result
				self._discovery_cache[cache_key] = (now, config)

				# Update provider with discovered endpoints
				if not provider.authorization_endpoint:
					provider.authorization_endpoint = config.get("authorization_endpoint")
				if not provider.token_endpoint:
					provider.token_endpoint = config.get("token_endpoint")
				if not provider.userinfo_endpoint:
					provider.userinfo_endpoint = config.get("userinfo_endpoint")
				if not provider.jwks_uri:
					provider.jwks_uri = config.get("jwks_uri")
				if not provider.end_session_endpoint:
					provider.end_session_endpoint = config.get("end_session_endpoint")

				return config

		except httpx.HTTPError as e:
			logger.error(f"OIDC discovery failed for {provider.issuer}: {e}")
			raise OIDCDiscoveryError(f"Failed to discover OIDC configuration: {e}")

	def create_authorization_url(
		self,
		provider: OIDCProvider,
		redirect_uri: str,
		extra_params: dict[str, str] | None = None,
	) -> tuple[str, OIDCAuthRequest]:
		"""
		Create authorization URL with PKCE.

		Returns:
			Tuple of (authorization_url, auth_request)
		"""
		assert provider.authorization_endpoint, "Authorization endpoint required"

		# Generate PKCE challenge
		code_verifier = secrets.token_urlsafe(64)
		code_challenge = base64.urlsafe_b64encode(
			hashlib.sha256(code_verifier.encode()).digest()
		).rstrip(b"=").decode()

		# Generate state and nonce
		state = secrets.token_urlsafe(32)
		nonce = secrets.token_urlsafe(32)

		# Build authorization request
		params = {
			"response_type": "code",
			"client_id": provider.client_id,
			"redirect_uri": redirect_uri,
			"scope": " ".join(provider.scopes),
			"state": state,
			"nonce": nonce,
			"code_challenge": code_challenge,
			"code_challenge_method": "S256",
		}

		if extra_params:
			params.update(extra_params)

		# Create auth request for later validation
		auth_request = OIDCAuthRequest(
			state=state,
			nonce=nonce,
			code_verifier=code_verifier,
			provider_id=provider.id,
			redirect_uri=redirect_uri,
		)

		# Store pending request (in production, use Redis/DB)
		self._pending_requests[state] = auth_request

		url = f"{provider.authorization_endpoint}?{urlencode(params)}"
		return url, auth_request

	async def exchange_code(
		self,
		provider: OIDCProvider,
		code: str,
		state: str,
	) -> OIDCTokenResponse:
		"""Exchange authorization code for tokens."""
		# Validate state and get auth request
		auth_request = self._pending_requests.pop(state, None)
		if not auth_request:
			raise OIDCValidationError("Invalid or expired state")

		if auth_request.provider_id != provider.id:
			raise OIDCValidationError("Provider mismatch")

		# Check request age (10 minute max)
		if datetime.utcnow() - auth_request.created_at > timedelta(minutes=10):
			raise OIDCValidationError("Authorization request expired")

		assert provider.token_endpoint, "Token endpoint required"

		# Build token request
		data = {
			"grant_type": "authorization_code",
			"code": code,
			"redirect_uri": auth_request.redirect_uri,
			"client_id": provider.client_id,
			"code_verifier": auth_request.code_verifier,
		}

		headers = {"Content-Type": "application/x-www-form-urlencoded"}

		# Add client authentication
		if provider.client_secret:
			if provider.client_authentication_method == "client_secret_basic":
				import base64
				credentials = base64.b64encode(
					f"{provider.client_id}:{provider.client_secret}".encode()
				).decode()
				headers["Authorization"] = f"Basic {credentials}"
			else:  # client_secret_post (default)
				data["client_secret"] = provider.client_secret

		try:
			async with httpx.AsyncClient() as client:
				response = await client.post(
					provider.token_endpoint,
					data=data,
					headers=headers,
					timeout=30.0,
				)

				if response.status_code != 200:
					error_data = response.json() if response.text else {}
					error_msg = error_data.get("error_description", error_data.get("error", "Unknown error"))
					raise OIDCTokenError(f"Token exchange failed: {error_msg}")

				return OIDCTokenResponse(**response.json())

		except httpx.HTTPError as e:
			raise OIDCTokenError(f"Token request failed: {e}")

	async def get_jwks(self, provider: OIDCProvider) -> dict:
		"""Get JSON Web Key Set for token validation."""
		assert provider.jwks_uri, "JWKS URI required"

		cache_key = provider.jwks_uri
		now = datetime.utcnow()

		# Check cache (1 hour TTL)
		if cache_key in self._jwks_cache:
			cached_at, jwks = self._jwks_cache[cache_key]
			if now - cached_at < timedelta(hours=1):
				return jwks

		try:
			async with httpx.AsyncClient() as client:
				response = await client.get(provider.jwks_uri, timeout=10.0)
				response.raise_for_status()
				jwks = response.json()
				self._jwks_cache[cache_key] = (now, jwks)
				return jwks

		except httpx.HTTPError as e:
			raise OIDCValidationError(f"Failed to fetch JWKS: {e}")

	async def validate_id_token(
		self,
		provider: OIDCProvider,
		id_token: str,
		nonce: str | None = None,
	) -> dict[str, Any]:
		"""Validate and decode ID token."""
		jwks = await self.get_jwks(provider)

		try:
			# Decode and validate
			claims = jwt.decode(
				id_token,
				jwks,
				algorithms=["RS256", "ES256"],
				audience=provider.client_id,
				issuer=provider.issuer,
				options={
					"verify_at_hash": False,  # Not always present
				},
			)

			# Validate nonce if provided
			if nonce and claims.get("nonce") != nonce:
				raise OIDCValidationError("Nonce mismatch")

			return claims

		except ExpiredSignatureError:
			raise OIDCValidationError("ID token expired")
		except JWTError as e:
			raise OIDCValidationError(f"Invalid ID token: {e}")

	async def get_userinfo(
		self,
		provider: OIDCProvider,
		access_token: str,
	) -> dict[str, Any]:
		"""Fetch user info from userinfo endpoint."""
		if not provider.userinfo_endpoint:
			return {}

		try:
			async with httpx.AsyncClient() as client:
				response = await client.get(
					provider.userinfo_endpoint,
					headers={"Authorization": f"Bearer {access_token}"},
					timeout=10.0,
				)
				response.raise_for_status()
				return response.json()

		except httpx.HTTPError as e:
			logger.warning(f"Failed to fetch userinfo: {e}")
			return {}

	def extract_user_info(
		self,
		provider: OIDCProvider,
		claims: dict[str, Any],
		userinfo: dict[str, Any] | None = None,
	) -> OIDCUserInfo:
		"""Extract user info from claims using provider's claim mappings."""
		# Merge claims and userinfo (userinfo takes precedence)
		all_claims = {**claims}
		if userinfo:
			all_claims.update(userinfo)

		# Extract using configured claim names
		username = all_claims.get(provider.username_claim)
		email = all_claims.get(provider.email_claim)
		first_name = all_claims.get(provider.first_name_claim)
		last_name = all_claims.get(provider.last_name_claim)

		# Extract groups and roles
		groups = []
		if provider.groups_claim and provider.groups_claim in all_claims:
			groups_raw = all_claims[provider.groups_claim]
			if isinstance(groups_raw, list):
				groups = groups_raw
			elif isinstance(groups_raw, str):
				groups = [groups_raw]

		roles = []
		if provider.roles_claim and provider.roles_claim in all_claims:
			roles_raw = all_claims[provider.roles_claim]
			if isinstance(roles_raw, list):
				roles = roles_raw
			elif isinstance(roles_raw, str):
				roles = [roles_raw]

		# Fallback for username
		if not username:
			username = email or all_claims.get("sub")

		return OIDCUserInfo(
			sub=all_claims.get("sub", ""),
			username=username,
			email=email,
			email_verified=all_claims.get("email_verified", False),
			first_name=first_name,
			last_name=last_name,
			picture=all_claims.get("picture"),
			groups=groups,
			roles=roles,
			raw_claims=all_claims,
		)

	def create_logout_url(
		self,
		provider: OIDCProvider,
		id_token_hint: str | None = None,
		post_logout_redirect_uri: str | None = None,
	) -> str | None:
		"""Create logout URL for single sign-out."""
		if not provider.end_session_endpoint:
			return None

		params = {}
		if id_token_hint:
			params["id_token_hint"] = id_token_hint
		if post_logout_redirect_uri:
			params["post_logout_redirect_uri"] = post_logout_redirect_uri

		if params:
			return f"{provider.end_session_endpoint}?{urlencode(params)}"
		return provider.end_session_endpoint


# Global service instance
oidc_service = OIDCService()
