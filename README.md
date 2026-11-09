# yketh

Sign Ethereum transactions with a **YubiKey 5** (firmware ≥ 5.2). The secp256k1 private key is generated inside the key and never leaves it, and the tool can export a **cryptographic proof of non-exportability** that anyone can check offline.

The command line follows [hw-wallet-cli-spec](https://github.com/mab-xyz/hw-wallet-cli-spec), shared with `tkey-eth` (Tillitis TKey): same commands, flags and JSON.

## How it works

YubiKey firmware is closed and can't be updated, and there is no Java Card runtime, so you can't install a custom applet. The built-in **OpenPGP applet**, however, supports ECDSA over secp256k1. Its `PSO:COMPUTE DIGITAL SIGNATURE` command (INS `2A`, P1P2 `9E9A`) signs any 32-byte digest and returns a raw `r‖s`. `yketh` talks to it directly with `yubikit` (no GnuPG). The host does the Ethereum-specific parts:

- `keccak256` of the unsigned transaction (EIP-1559/2930/… typed, or legacy EIP-155) or of the EIP-191 message;
- low-s normalization (EIP-2);
- the recovery id `v`, found by trying both parities against the card's public key;
- RLP encoding of the signed transaction.

PIV is not usable for this: it has no secp256k1.

## Proof of non-exportability

`yketh attest` asks the card for an OpenPGP **attestation certificate** for the signature key. Its chain is:

```
YubiKey OPGP Attestation SIG      ← attested key = your Ethereum key, ext 1.3.6.1.4.1.41482.5.2 = 0x01 (generated on device)
  ↳ Yubikey OPGP Attestation      ← per-device key, burned in at the factory
    ↳ Yubico OPGP Attestation B2 1
      ↳ Yubico Attestation Intermediate B 1
        ↳ Yubico Attestation Root 1   (bundled in yketh/cas/, from developers.yubico.com/PKI)
```

A key generated on the card can't be exported, and an imported key would carry a different key-source value. `verify` checks the following (its JSON has `"kind": "yubico-opgp"`):

- every signature in the chain, up to a bundled Yubico root;
- key source = generated;
- the address derived from the attested public key equals `--address`.

## Install

```
uv venv && uv pip install -e '.[dev]'
```

## Usage

```
yketh info                                   # SIG slot: algorithm, key status (GENERATED/IMPORTED), touch
yketh generate                               # ⚠️ replaces the OpenPGP signature key; prints the address
yketh address                                # pubkey= and address= lines; --json for JSON
yketh sign-tx --tx tests/tx1559.json         # JSON with raw_transaction (0x02…) for eth_sendRawTransaction
yketh sign-personal --message "hello"        # EIP-191 personal_sign (or --message-hex, --message-file)
yketh sign-typed-data --typed-data td.json   # EIP-712 (types, primaryType, domain, message)
yketh sign-digest --digest 0x…               # a raw 32-byte digest
yketh attest --out proof.pem                 # attestation bundle (leaf + device cert)
yketh verify --cert proof.pem --address 0x…  # offline, no card needed
yketh touch on                               # require a physical touch per signature
```

The `sign-*` commands print one JSON object, for example `sign-personal`:

```json
{"address": "0x…", "digest": "0x…", "signature": "0x…"}
```

`signature` is r‖s‖v (65 bytes, low s, v = 27 or 28) for every sign command; `--tx` and `--typed-data` read `-` as stdin. `--device SERIAL` picks a YubiKey when several are connected. `address`, `info`, `generate`, `touch`, `attest` and `verify` take `--json`. Errors go to stderr with exit code 1.

PINs are read from `YKETH_PIN` / `YKETH_ADMIN_PIN`, else from the file named by `YKETH_PIN_FILE` / `YKETH_ADMIN_PIN_FILE` (must be `chmod 600`), or asked for interactively. For unattended signing (no PIN prompt, no touch): `yketh touch off`, then `YKETH_PIN_FILE=~/.config/yketh/pin`. The OpenPGP defaults are `123456` / `12345678`. Change them:

```
ykman openpgp access change-pin
ykman openpgp access change-admin-pin
```

## Performance

Measured on a YubiKey 5C Nano (fw 5.8.0), Python 3.13, i9-10900K:

| | time |
|---|---|
| card: one `PSO:CDS` signature + recovery id (median of 40, range 87–93 ms) | 88 ms |
| card: connect 18 ms, verify PIN 10 ms, read public key 10 ms | ~40 ms |
| `yketh sign-personal` (new process each call) | ~0.37 s |

The signature itself is the floor, and no host code can go below it. A `yketh` call adds the interpreter and import time (~0.18 s, mostly `eth_keys`) and the card connection and PIN check.

What keeps the CLI fast:

- Only the smart-card interface is scanned (`list_ccid_devices`, 3 ms). `list_all_devices` also walks HID and FIDO and cost 35–170 ms. The serial is read only for `info` and `--device`.
- `eth_account` costs ~0.4 s to import (py_ecc BLS tables), so only `sign-tx` imports it. `sign-personal` hashes EIP-191 directly. The attestation code (`cryptography` x509) loads only for `attest` and `verify`.

For repeated signing, hold one session in a long-running process: open the card once, verify the PIN once ("PIN once" is the card default), then call `Card.sign_digest` and `_eth.sign_digest` per request. That costs ~88 ms per signature instead of ~0.37 s. Do not run two `yketh` processes at the same time: the card is a single PC/SC resource, so concurrent calls fail or wait. Reproduce the numbers with `scripts/bench.py`.

## Tests

```
pytest                    # unit tests, no card; attestation logic tested on a synthetic CA chain; the CLI is checked against hw-wallet-cli-spec
YKETH_PIN_FILE=~/.config/yketh/pin pytest -m hardware -o addopts=   # signs + attests with the plugged-in card against the real Yubico roots (does not regenerate; skipped without a PIN)
```

## License

MIT
