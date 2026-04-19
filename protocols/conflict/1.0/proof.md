# Conflict Proof Protocol v1.0

## Zweck
Dieses Protokoll dient der Verbreitung von kryptographisch verifizierbaren Beweisen für Double-Spending-Versuche. Da das Human Money System "offline-first" ist, können Double-Spends nicht technisch verhindert, aber im Nachhinein zweifelsfrei bewiesen werden. Ein solcher Beweis ermöglicht es dem Netzwerk, den Verursacher zu identifizieren und soziale oder rechtliche Konsequenzen zu ziehen.

## Schema Definition
Der Payload entspricht dem JSON des Structs `ProofOfDoubleSpend` (definiert in `src/models/conflict.rs`).

Die wichtigsten Felder des Objekts sind:

- **proof_id**: Eine eindeutige, deterministische ID des Konflikts, berechnet aus `hash(offender_id + fork_point_prev_hash)`.
- **offender_id**: Die DID des Senders, der den Double Spend durchgeführt hat.
- **fork_point_prev_hash**: Der kryptographische Ankerpunkt (letzter gültiger Status), von dem die betrügerischen Transaktionen abzweigen.
- **conflicting_transactions**: Ein Array mit den (mindestens) zwei widersprüchlichen `Transaction` Objekten. Da beide dieselbe Basis (`prev_hash`) referenzieren, aber unterschiedliche Ausgaben tätigen, ist der Betrug mathematisch belegt.
- **reporter_id**: Die DID der Partei, die den Konflikt entdeckt und diesen Beweis erstellt hat.
- **reporter_signature**: Die Signatur des Reporters über die `proof_id`.

## Beispiel (Schematisch)
```json
{
  "proof_id": "p_556_abc",
  "offender_id": "did:key:z6M_BadActor...",
  "fork_point_prev_hash": "2f71...a8e",
  "conflicting_transactions": [
    {
      "t_id": "tx_alpha",
      "amount": "10",
      "recipient_id": "did:key:z6M_Victim_1...",
      "prev_hash": "2f71...a8e"
    },
    {
      "t_id": "tx_beta",
      "amount": "10",
      "recipient_id": "did:key:z6M_Victim_2...",
      "prev_hash": "2f71...a8e"
    }
  ],
  "reporter_id": "did:key:z6M_Networknode_99...",
  "reporter_signature": "6Gf...777abc",
  "report_timestamp": "2024-05-21T09:30:00Z"
}
```
