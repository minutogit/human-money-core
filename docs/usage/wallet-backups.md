# Encrypted differential wallet backups

`AppService::create_differential_backup`, `inspect_backup`, and `restore_backup`
provide a transport-independent backup boundary. Applications supply local files,
cloud object APIs, WebDAV, or relay transport; the core makes no network calls.
Types are exported from `human_money_core::models::backup`.

Use `BackupProtection::MnemonicOnly` by default. The exported profile retains its
mnemonic slot but replaces the local password slot and salt with random bytes.
`CustomBackupPassword` instead wraps the existing file key with a separate password.
The original profile and all other local bytes remain unchanged. Password strength
is the application's responsibility; an empty backup password is rejected.

The manifest encrypts identity, names, seal, inventory, and hashes. Blob names use
truncated HMAC-SHA3-256. Object sizes, counts, and upload timing remain visible.
The manifest contains a separately signed inventory of exported bytes, including
`seal.enc`, because the transformed profile differs from the local integrity record.
The local integrity record is verified before export and recreated after restore.

For password protection, a public salt derives the envelope key and a separate
identity-wrapped copy enables mnemonic recovery of the same manifest. No password
or mnemonic is stored in the manifest. Credentials must include the original
BIP-39 passphrase when one was used. The existing identity derivation is preserved.

Pass the last committed manifest to create a diff. Reusing its salt preserves blob
names for password backups. An unchanged profile reuses the prior transformed blob,
so randomized key wrapping does not cause uploads on every backup. Changing the
protection mode or backup password requires a new full backup. Retain the complete
remote blob set: `put_blobs` alone is only sufficient for a full initial backup.
Differencing compares encrypted bytes; existing wallet saves can re-encrypt otherwise
unchanged stores, which then count as changed files.

Blob names are stable within a series. Applications must serialize uploads and
restore access, or use a separate destination generation and publish it only after
all writes and `manifest.enc` are complete. Replacing only the manifest atomically
does not make a multi-object update atomic. Apply `delete_blobs` after publication.
Keep a previous committed generation if upload interruption recovery is required.

Inspection verifies the seal signature, inventory signature, seal binding, supported
versions, and canonical paths. It exposes `manifest.seal.payload` (epoch, nonce,
identity, timestamp) and compares against the currently unlocked matching account.
Inspection cannot check blob bytes until they have been downloaded.

Restore requires the exact full blob set. It validates paths, names, and hashes
before staging any files. It then authenticates the profile, verifies the stored
seal matches the manifest, changes the local password, creates a device-bound
recovery epoch, and regenerates local integrity. A normal login verifies the staged
state before a directory rename activates it. Native Unix writes synchronize files
and directories. The profile index is replaced durably after the new directory is
ready; interruption before indexing can leave a recoverable orphan directory.
Existing wallets are preserved: a restored copy receives a random local folder.

The returned anchor query refers to the original backup seal, and voucher queries
refer to its active outputs. Send these through the application's trusted L2 flow,
verify responses, then call `reconcile_rollback_with_diagnostics` with the spent
voucher IDs and authoritative nonce. Restore itself performs no network queries
and cannot determine whether offline outputs have already been spent elsewhere.
