# yketh

Sign Ethereum transactions with a **YubiKey 5** (firmware ≥ 5.2). The secp256k1 private key is generated inside the key and never leaves it, and the tool can export a **cryptographic proof of non-exportability** that anyone can check offline.

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

A key generated on the card can't be exported, and an imported key would carry a different key-source value. `verify-attestation` checks the following:

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
yketh address
yketh sign-tx tests/tx1559.json              # prints the raw signed tx (0x02…), ready for eth_sendRawTransaction
yketh sign-msg "hello"                       # EIP-191 personal_sign, 65-byte r‖s‖v
yketh attest -o proof.pem                    # attestation bundle (leaf + device cert)
yketh verify-attestation proof.pem --address 0x…   # offline, no card needed
yketh touch on                               # require a physical touch per signature
```

Every command accepts `--json` and `--serial`. PINs are read from `YKETH_PIN` / `YKETH_ADMIN_PIN`, or asked for interactively. The OpenPGP defaults are `123456` / `12345678`. Change them:

```
ykman openpgp access change-pin
ykman openpgp access change-admin-pin
```

## Tests

```
pytest                    # unit tests, no card; attestation logic tested on a synthetic CA chain
pytest -m hardware -o addopts=   # signs + attests with the plugged-in card against the real Yubico roots (does not regenerate)
```

## License

MIT
