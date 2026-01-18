from uuid import UUID
from enum import Enum
from pydantic import BaseModel, ConfigDict


class User(BaseModel):
    id: UUID
    username: str
    password: str
    email: str
    home_folder_id: UUID | None = None
    inbox_folder_id: UUID | None = None
    is_superuser: bool = False
    scopes: list[str] = []

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class TokenData(BaseModel):
    sub: str  # same as `user_id`
    preferred_username: str  # standard claim for `username`
    email: str
    scopes: list[str] = []

    model_config = ConfigDict(from_attributes=True)


class UserCredentials(BaseModel):
    username: str
    password: str

    model_config = ConfigDict(from_attributes=True)


class Group(BaseModel):
    id: UUID
    name: str

    # Config
    model_config = ConfigDict(from_attributes=True)


class Role(BaseModel):
    id: UUID
    name: str

    # Config
    model_config = ConfigDict(from_attributes=True)


class Permission(BaseModel):
    id: UUID
    name: str  # e.g. "Can create tags"
    codename: str  # e.g. "tag.create"

    # Config
    model_config = ConfigDict(from_attributes=True)


# (c) Copyright Datacraft, 2026
# 2FA and Passkey Schemas


class TOTPSetupRequest(BaseModel):
    """Request to set up TOTP."""
    pass  # No fields needed


class TOTPSetupResponse(BaseModel):
    """Response with TOTP setup data."""
    success: bool
    secret_key: str | None = None
    provisioning_uri: str | None = None
    backup_codes: list[str] | None = None
    message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class TOTPVerifyRequest(BaseModel):
    """Request to verify a TOTP code."""
    code: str


class TOTPVerifyResponse(BaseModel):
    """Response from TOTP verification."""
    success: bool
    message: str | None = None
    used_backup_code: bool = False

    model_config = ConfigDict(from_attributes=True)


class TOTPDisableRequest(BaseModel):
    """Request to disable TOTP."""
    code: str


class TOTPStatusResponse(BaseModel):
    """Response with TOTP status."""
    enabled: bool
    backup_codes_remaining: int | None = None

    model_config = ConfigDict(from_attributes=True)


class PasskeyRegistrationStartRequest(BaseModel):
    """Request to start passkey registration."""
    device_name: str | None = None


class PasskeyRegistrationStartResponse(BaseModel):
    """Response with WebAuthn registration options."""
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

    model_config = ConfigDict(from_attributes=True)


class PasskeyRegistrationCompleteRequest(BaseModel):
    """Request to complete passkey registration."""
    challenge: str
    credential: dict


class PasskeyAuthenticationStartRequest(BaseModel):
    """Request to start passkey authentication."""
    username: str | None = None


class PasskeyAuthenticationStartResponse(BaseModel):
    """Response with WebAuthn authentication options."""
    challenge: str
    rp_id: str
    timeout: int
    allow_credentials: list[dict]
    user_verification: str

    model_config = ConfigDict(from_attributes=True)


class PasskeyAuthenticationCompleteRequest(BaseModel):
    """Request to complete passkey authentication."""
    challenge: str
    credential: dict


class PasskeyResponse(BaseModel):
    """Generic passkey operation response."""
    success: bool
    credential_id: str | None = None
    message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class PasskeyCredentialInfo(BaseModel):
    """Information about a passkey credential."""
    id: str
    device_name: str | None = None
    device_type: str | None = None
    created_at: str | None = None
    last_used_at: str | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class PasskeyListResponse(BaseModel):
    """Response with list of passkeys."""
    credentials: list[PasskeyCredentialInfo]

    model_config = ConfigDict(from_attributes=True)


class MFALoginRequest(BaseModel):
    """Login request that may include MFA."""
    username: str
    password: str
    totp_code: str | None = None


class MFALoginResponse(BaseModel):
    """Login response that may require MFA."""
    access_token: str | None = None
    token_type: str = "bearer"
    requires_mfa: bool = False
    mfa_methods: list[str] = []
    mfa_session_token: str | None = None

    model_config = ConfigDict(from_attributes=True)


class MFAVerifyRequest(BaseModel):
    """Request to verify MFA during login."""
    mfa_session_token: str
    code: str
    method: str = "totp"  # totp, backup, passkey
