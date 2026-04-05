# 🔐 Secure Financial Transaction System

Hybrid encryption system for securing simulated financial transactions using **AES-256-GCM** for data encryption and **RSA-2048** for key exchange. Includes digital signatures for tamper detection and a benchmark tool validated across **10,000+ transactions** with zero integrity failures.

![Java](https://img.shields.io/badge/Java-17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)
![AES-256](https://img.shields.io/badge/AES--256-GCM-blue?style=flat-square)
![RSA-2048](https://img.shields.io/badge/RSA--2048-OAEP-green?style=flat-square)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)

---

## how it works

This implements **hybrid encryption** — the same approach used by TLS/HTTPS under the hood:

```
SENDER                                          RECEIVER
──────                                          ────────
Generate AES-256 session key
Encrypt transaction with AES ──────────────────→ Decrypt with AES key
Encrypt AES key with receiver's RSA public key → Decrypt AES key with RSA private key
Sign payload with sender's RSA private key ────→ Verify signature with sender's public key
```

**Why hybrid?** AES is fast for encrypting data but requires sharing a secret key. RSA can securely transmit the key but is too slow for bulk data. Combine them: AES encrypts the data, RSA protects the AES key.

## quick start

```bash
# compile
mkdir -p out
javac -d out $(find src/main/java -name "*.java")

# run demo
java -cp out com.securepay.Main

# run benchmark (10,000 transactions)
java -cp out com.securepay.Main --benchmark 10000

# or use the build script
chmod +x build.sh
./build.sh          # demo
./build.sh bench    # benchmark
```

## project structure

```
src/main/java/com/securepay/
├── Main.java                      # entry point with demos
├── crypto/
│   ├── AESEncryptor.java          # AES-256-GCM encryption/decryption
│   └── RSAKeyExchange.java        # RSA-2048 key exchange + digital signatures
├── model/
│   └── Transaction.java           # transaction data model
├── service/
│   └── TransactionService.java    # orchestrates the full security flow
└── util/
    └── TransactionBenchmark.java  # bulk testing tool (10K+ transactions)
```

## what the demo shows

1. **AES-256-GCM encryption** — encrypts sensitive card data, decrypts it back, verifies match
2. **RSA key exchange** — Alice encrypts her AES key with Bob's public key, Bob recovers it
3. **Full transaction flow** — create tx → encrypt → sign → verify → decrypt
4. **Tamper detection** — modifies encrypted payload, system catches it immediately
5. **Integrity test** — runs 100 transactions through the full cycle

## security choices

| Component | Choice | Why |
|-----------|--------|-----|
| Symmetric cipher | AES-256-GCM | Authenticated encryption — provides confidentiality AND integrity in one step. No padding oracle attacks |
| Asymmetric cipher | RSA-2048 OAEP | OAEP padding resists Bleichenbacher's attack (PKCS1v1.5 doesn't) |
| Signatures | SHA256withRSA | Standard, widely supported, provides non-repudiation |
| IV handling | Random 12-byte IV per encryption | GCM requires unique IVs — reuse completely breaks security |
| Key size | AES-256 + RSA-2048 | Balanced security vs performance. RSA-4096 would be overkill here |

## benchmark results

Tested on M1 MacBook Air, Java 17:

```
Transactions:     10,000
Passed:           10,000 (100%)
Failed:           0
Total time:       ~45 seconds
Throughput:       ~220 tx/sec
Avg encrypt:      ~2.1 ms/tx
Avg decrypt:      ~2.3 ms/tx
```

## what I learned

- GCM mode is strictly better than CBC for most use cases (authenticated encryption for free)
- Never reuse IVs/nonces with GCM — it's not just bad practice, it completely compromises the key
- RSA can only encrypt data shorter than the key size, which is why you encrypt a symmetric key with it, not the actual data
- OAEP padding adds randomness, so encrypting the same plaintext twice gives different ciphertext (this is a feature, not a bug)

## team

Built by a 4-member team at VIT Vellore using Git for version control and structured sprint planning.

- **Lokesh Reddy Elluri** — Lead developer, encryption architecture
- Team members — Testing, documentation, integration

---

**Lokesh Reddy Elluri** — MS Data Science, Indiana University Bloomington
[LinkedIn](https://linkedin.com/in/lokesh-reddy-elluri-a77a7b201) · [Email](mailto:redfylokesh@gmail.com)
