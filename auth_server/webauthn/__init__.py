# (c) Copyright Datacraft, 2026
"""WebAuthn/FIDO2 Passkey authentication module."""

from .service import (
	WebAuthnService,
	WebAuthnCredential,
	RegistrationOptions,
	AuthenticationOptions,
)
from .router import router

__all__ = [
	"WebAuthnService",
	"WebAuthnCredential",
	"RegistrationOptions",
	"AuthenticationOptions",
	"router",
]
