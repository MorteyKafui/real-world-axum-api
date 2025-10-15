-- Add migration script here
ALTER TABLE refresh_tokens RENAME COLUMN last_updated TO last_used_at;
