# Identity outbox encryption-key rotation

This runbook applies to generated PostgreSQL services using the optional
\`auth_http\` / \`auth_smtp\` modules. It does not provision a secret manager.

## Invariants

- New queued messages store \`encryption_key_id\`, authenticated together
  with the token digest using ChaCha20-Poly1305 AEAD.
- The active key is **encrypt + decrypt**; previous keys are **decrypt-only**.
- Existing rows from before migration are labeled \`legacy\`; they still use
  the old digest-only associated data. New rows, including those using
  the \`legacy\` ID, use versioned associated data.
- A worker refuses work if any pending encrypted message uses a key ID it
  cannot resolve. Such messages retain their retry budget and ciphertext.
- Never print key values in logs, alert labels, or source control.

## Initial upgrade (unversioned to versioned)

1. Back up PostgreSQL and record the current production key securely.
   Test backup restoration on a nonproduction environment.
2. Apply migration \`20261104000007_outbox_key_version.sql\`. It adds
   \`encryption_key_id TEXT NOT NULL DEFAULT 'legacy'\`, preserving all
   already-encrypted queued records.
3. **Stop old email workers before upgrading API processes.** An old worker
   cannot read the new authenticated payload format, even if the key bytes
   are unchanged. Deploy the upgraded worker first with the original
   \`IDENTITY_OUTBOX_KEY_HEX\` and no key ID (defaults to \`legacy\`).
4. Deploy the upgraded API with the same configuration. Ensure all replicas
   use the same immutable \`OutboxKeyring\` snapshot.
5. Inspect \`identity_outbox::stats(pool)\`, failed deliveries, and the
   PostgreSQL backlog to verify no messages were lost.

Do not mix old and new worker binaries during this upgrade.

## Rotate the key

1. Generate a cryptographically random **new** 32-byte key through your
   secret-management system. Choose a unique key ID, e.g. \`v20261104\`.
2. Configure *every* worker and API replica with:
   - \`IDENTITY_OUTBOX_KEY_ID=v20261104\`
   - \`IDENTITY_OUTBOX_KEY_HEX=<new 64-hex-byte key>\`
   - \`IDENTITY_OUTBOX_PREVIOUS_KEYS=legacy=<old 64-hex-byte key>\`
     (add other previous \`ID=hex\` entries separated by commas if needed)
3. Roll out workers with both keys available **before** new API replicas
   start creating messages under the new ID. Avoid versions with different
   active keys running at the same time when possible; encryption remains
   decryptable only if the workers have all referenced IDs.
4. Monitor pending/dead counters and delivery latency. Key IDs are metadata,
   not secrets; ciphertext and key bytes must remain protected.
5. Before removing an old key, run
   \`identity_outbox::encrypted_pending_for_key(pool, "legacy")\`.
   Retire a previous key only after the result reaches **zero** and workers
   using the old configuration have been stopped. A queued message encrypted
   by the retired key cannot be recovered without it.

## Rollback, missing keys and disaster recovery

- Roll back to a version that understands **all currently used key IDs**.
  A binary from before this migration cannot decrypt newer ciphertext.
  Thus application rollbacks must use the upgraded binary with the previous
  active key, not revert to the old unversioned worker.
- A missing-key error is an operational incident: restore the correct old
  key and restart the affected worker. Do not overwrite key IDs or edit
  ciphertext manually.
- If an encryption key is irretrievably lost, the queued token messages
  using it cannot be recovered. Invalidate the affected one-time tokens and
  have users request new verification/reset messages; communicate the impact.
- If a key is compromised, prioritize containment and re-issuance over
  retaining compromised pending payloads. Review access logs and rotate
  credentials under incident-response procedures.
- Export metrics and alert on missing keys, dead-letter growth, and
  queue age. Independently verify the backup/recovery process.

## Configuration format

\`IDENTITY_OUTBOX_KEY_ID\` accepts 1–32 ASCII letters, digits, underscore
and hyphen. \`IDENTITY_OUTBOX_KEY_HEX\` is exactly 64 hexadecimal characters.
\`IDENTITY_OUTBOX_PREVIOUS_KEYS\` is a comma-separated list of
\`ID=64hex\`. Duplicate or malformed IDs fail startup; never allow the same
ID with two different keys.

**Security caveat:** prior keys remain sensitive until revoked at the
secret manager, backup retention has elapsed, and no pending ciphertext
depends on them.
