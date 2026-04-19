# Signing Response Protocol v1.0

## Zweck
Dieses Protokoll beschreibt die Antwort eines Bürgen oder Notars auf eine zuvor empfangene Signaturanfrage. Da der Bürge den Gutschein nicht direkt verändert, sendet er eine "losgelöste" (detached) Signatur zurück. Der Ersteller kann diese Signatur anschließend in sein lokales Voucher-Objekt integrieren.

## Schema Definition
Der Payload ist ein JSON-Objekt des Structs `DetachedSignature` (definiert in `src/models/signature.rs`). Es handelt sich um ein Enum, das eine `VoucherSignature` kapselt.

Die Felder innerhalb der Signatur-Struktur sind:

- **voucher_id**: Die eindeutige ID des Gutscheins, auf den sich diese Signatur bezieht.
- **signature_id**: Eine eindeutige ID für dieses spezifische Signatur-Objekt.
- **signer_id**: Die DID des Unterzeichners.
- **signature**: Die eigentliche kryptographische Signatur (Ed25519) über die Daten des Gutscheins.
- **signature_time**: Der Zeitpunkt der Unterzeichnung (ISO 8601).
- **role**: Der Zweck der Signatur, z.B. `"guarantor"` (Bürge) oder `"notary"` (Notar).
- **details**: (Optional) Ein `PublicProfile` des Unterzeichners, um dem Empfänger die Verifizierung ohne externe Datenbankabfrage zu ermöglichen.

## Beispiel (Schematisch)
```json
{
  "Signature": {
    "voucher_id": "v778...x9",
    "signature_id": "sig_abc_123",
    "signer_id": "did:key:z6M_Buerge_789...",
    "signature": "kJH67...99S0x",
    "signature_time": "2024-05-20T12:05:00Z",
    "role": "guarantor",
    "details": {
      "organization": "Regionale Tauschgemeinschaft Süd",
      "community": "Human Money"
    }
  }
}
```
