-- Add migration script here
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
