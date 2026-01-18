-- (c) Copyright Datacraft, 2026
-- Migration: Add 2FA and Passkey tables

-- Two-Factor Authentication table
CREATE TABLE IF NOT EXISTS two_factor_auth (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret_key VARCHAR(64) NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    is_verified BOOLEAN DEFAULT FALSE,
    backup_codes JSONB,
    recovery_email VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_2fa_user_id ON two_factor_auth(user_id);

-- Passkey/WebAuthn Credentials table
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER DEFAULT 0,
    device_name VARCHAR(100),
    device_type VARCHAR(50),
    aaguid BYTEA,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_passkey_user_id ON passkey_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credential_id ON passkey_credentials(credential_id);

-- Active Authentication Sessions table
CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    device_fingerprint VARCHAR(64),
    is_mfa_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_user_id ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_session_token ON auth_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_session_expires ON auth_sessions(expires_at);

-- Login Attempts tracking table
CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(150) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500),
    success BOOLEAN DEFAULT FALSE,
    failure_reason VARCHAR(100),
    mfa_method VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_created ON login_attempts(created_at);

-- Add comment for documentation
COMMENT ON TABLE two_factor_auth IS 'TOTP-based two-factor authentication settings per user';
COMMENT ON TABLE passkey_credentials IS 'WebAuthn/Passkey credentials for passwordless authentication';
COMMENT ON TABLE auth_sessions IS 'Active authentication sessions with MFA status';
COMMENT ON TABLE login_attempts IS 'Login attempt audit log for security monitoring';
