-- Add version column to agents table.
-- Extracted from the ad_json blob so version can be indexed and filtered.
ALTER TABLE agents ADD COLUMN version TEXT NOT NULL DEFAULT '0.1.0';

-- Backfill from JSON blob for existing rows.
UPDATE agents SET version = (ad_json::json->>'version')
    WHERE (ad_json::json->>'version') IS NOT NULL;
