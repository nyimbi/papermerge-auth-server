# OIDC Provider Models
# GitHub Issue #699: OIDC and Entra ID support
from enum import Enum
from typing import Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, field_validator
from uuid_extensions import uuid7str


class OIDCProviderType(str, Enum):
	"""Supported OIDC provider types."""
	GENERIC = "generic"
	ENTRA_ID = "entra_id"  # Microsoft Entra ID (formerly Azure AD)
	GOOGLE = "google"
	OKTA = "okta"
	AUTH0 = "auth0"
	KEYCLOAK = "keycloak"


class OIDCProvider(BaseModel):
	"""OIDC Provider configuration."""
	model_config = ConfigDict(extra="forbid")

	id: str = Field(default_factory=uuid7str)
	name: str = Field(..., min_length=1, max_length=100)
	provider_type: OIDCProviderType = OIDCProviderType.GENERIC
	enabled: bool = True
	is_default: bool = False

	# OIDC Endpoints (can be auto-discovered)
	issuer: str = Field(..., description="OIDC Issuer URL")
	authorization_endpoint: str | None = None
	token_endpoint: str | None = None
	userinfo_endpoint: str | None = None
	jwks_uri: str | None = None
	end_session_endpoint: str | None = None

	# Client credentials
	client_id: str = Field(..., min_length=1)
	client_secret: str | None = None  # None for public clients
	client_authentication_method: str = "client_secret_post"

	# Scopes
	scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])

	# Claim mappings
	username_claim: str = "preferred_username"
	email_claim: str = "email"
	first_name_claim: str = "given_name"
	last_name_claim: str = "family_name"
	groups_claim: str | None = "groups"
	roles_claim: str | None = "roles"

	# Behavior
	auto_create_users: bool = True
	auto_update_user_info: bool = True
	sync_groups: bool = False
	sync_roles: bool = False
	default_role_ids: list[str] = Field(default_factory=list)
	default_group_ids: list[str] = Field(default_factory=list)

	# Display
	display_name: str | None = None
	icon_url: str | None = None
	button_color: str | None = None

	# Timestamps
	created_at: datetime = Field(default_factory=datetime.utcnow)
	updated_at: datetime | None = None

	@field_validator("issuer")
	@classmethod
	def validate_issuer(cls, v: str) -> str:
		if not v.startswith("https://"):
			raise ValueError("Issuer must use HTTPS")
		return v.rstrip("/")


class EntraIDConfig(BaseModel):
	"""Microsoft Entra ID specific configuration."""
	model_config = ConfigDict(extra="forbid")

	tenant_id: str = Field(..., description="Azure AD Tenant ID")
	client_id: str = Field(..., description="Application (client) ID")
	client_secret: str = Field(..., description="Client secret value")
	scopes: list[str] = Field(
		default_factory=lambda: ["openid", "email", "profile", "User.Read"]
	)

	# Optional advanced settings
	use_v2_endpoint: bool = True
	allowed_groups: list[str] | None = None  # Filter by group membership
	admin_groups: list[str] | None = None  # Groups that get admin role

	def to_oidc_provider(self, name: str = "Microsoft") -> OIDCProvider:
		"""Convert to generic OIDCProvider."""
		base_url = "https://login.microsoftonline.com"
		version = "v2.0" if self.use_v2_endpoint else ""

		return OIDCProvider(
			name=name,
			provider_type=OIDCProviderType.ENTRA_ID,
			issuer=f"{base_url}/{self.tenant_id}/{version}".rstrip("/"),
			authorization_endpoint=f"{base_url}/{self.tenant_id}/oauth2/{version}/authorize".replace("//authorize", "/authorize"),
			token_endpoint=f"{base_url}/{self.tenant_id}/oauth2/{version}/token".replace("//token", "/token"),
			userinfo_endpoint="https://graph.microsoft.com/oidc/userinfo",
			jwks_uri=f"{base_url}/{self.tenant_id}/discovery/{version}/keys".replace("//keys", "/keys") if version else f"{base_url}/{self.tenant_id}/discovery/keys",
			end_session_endpoint=f"{base_url}/{self.tenant_id}/oauth2/{version}/logout".replace("//logout", "/logout"),
			client_id=self.client_id,
			client_secret=self.client_secret,
			scopes=self.scopes,
			groups_claim="groups",
			roles_claim="roles",
			display_name="Sign in with Microsoft",
			icon_url="https://login.microsoftonline.com/images/logo_microsoft.svg",
			button_color="#0078d4",
		)


class OIDCAuthRequest(BaseModel):
	"""OIDC authorization request state."""
	model_config = ConfigDict(extra="forbid")

	state: str
	nonce: str
	code_verifier: str
	provider_id: str
	redirect_uri: str
	created_at: datetime = Field(default_factory=datetime.utcnow)


class OIDCTokenResponse(BaseModel):
	"""Tokens received from OIDC provider."""
	access_token: str
	token_type: str = "Bearer"
	expires_in: int | None = None
	refresh_token: str | None = None
	id_token: str | None = None
	scope: str | None = None


class OIDCUserInfo(BaseModel):
	"""User info extracted from OIDC claims."""
	sub: str
	username: str | None = None
	email: str | None = None
	email_verified: bool = False
	first_name: str | None = None
	last_name: str | None = None
	picture: str | None = None
	groups: list[str] = Field(default_factory=list)
	roles: list[str] = Field(default_factory=list)
	raw_claims: dict[str, Any] = Field(default_factory=dict)


# Schema for API responses
class OIDCProviderPublic(BaseModel):
	"""Public OIDC provider info (no secrets)."""
	id: str
	name: str
	provider_type: OIDCProviderType
	enabled: bool
	display_name: str | None
	icon_url: str | None
	button_color: str | None
	authorization_endpoint: str | None

	@classmethod
	def from_provider(cls, provider: OIDCProvider) -> "OIDCProviderPublic":
		return cls(
			id=provider.id,
			name=provider.name,
			provider_type=provider.provider_type,
			enabled=provider.enabled,
			display_name=provider.display_name or provider.name,
			icon_url=provider.icon_url,
			button_color=provider.button_color,
			authorization_endpoint=provider.authorization_endpoint,
		)


class OIDCProviderCreate(BaseModel):
	"""Create OIDC provider request."""
	model_config = ConfigDict(extra="forbid")

	name: str = Field(..., min_length=1, max_length=100)
	provider_type: OIDCProviderType = OIDCProviderType.GENERIC
	issuer: str
	client_id: str
	client_secret: str | None = None
	scopes: list[str] | None = None
	auto_create_users: bool = True
	display_name: str | None = None


class OIDCProviderUpdate(BaseModel):
	"""Update OIDC provider request."""
	model_config = ConfigDict(extra="forbid")

	name: str | None = None
	enabled: bool | None = None
	is_default: bool | None = None
	client_secret: str | None = None
	scopes: list[str] | None = None
	auto_create_users: bool | None = None
	auto_update_user_info: bool | None = None
	sync_groups: bool | None = None
	display_name: str | None = None


class EntraIDProviderCreate(BaseModel):
	"""Create Entra ID provider request (simplified)."""
	model_config = ConfigDict(extra="forbid")

	name: str = "Microsoft"
	tenant_id: str = Field(..., description="Azure AD Tenant ID (GUID or domain)")
	client_id: str = Field(..., description="Application (client) ID")
	client_secret: str = Field(..., description="Client secret")
	auto_create_users: bool = True
	admin_groups: list[str] | None = None
