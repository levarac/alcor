CREATE TABLE IF NOT EXISTS challenges (
  challenge TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  event_key TEXT,
  event_key_address TEXT,
  app_signature TEXT,
  signal TEXT,
  bound_at INTEGER
);

CREATE TABLE IF NOT EXISTS credentials (
  event_id TEXT NOT NULL,
  event_key TEXT NOT NULL,
  event_key_address TEXT NOT NULL,
  nullifier_hash TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  challenge TEXT NOT NULL UNIQUE,
  app_signature TEXT NOT NULL,
  proof_digest TEXT NOT NULL,
  attestation TEXT NOT NULL,
  PRIMARY KEY (event_id, nullifier_hash),
  UNIQUE (event_id, event_key)
);

CREATE INDEX IF NOT EXISTS credentials_event ON credentials(event_id, verified_at);
