-- Add migration script here
ALTER TABLE refresh_tokens RENAME COLUMN updated_at TO last_updated;
