# Cipher Encryption Library

A Java library that shows, step by step, how classical, stream and block ciphers encrypt and decrypt.

> **Educational only, insecure, not for production.** The implementations favour readability over speed and side-channel resistance, and several of the algorithms (RC4, DES, ECB, dCTR) are broken on purpose or by age. Use a vetted library such as the JDK's `javax.crypto` for real data.

## Features

Classical ciphers (character-level, exposed as bytes through `TextCipherAdapter`):

- Affine, substitution, permutation, columnar transposition and Vigenère.

Stream ciphers (`StreamCipher` over a `Keystream`):

- RC4: key scheduling (KSA) and the PRGA.
- Salsa20/20: 16- or 32-byte key, 8-byte nonce, 64-bit block counter.
- ChaCha20 (RFC 8439): 32-byte key, 12-byte nonce, 32-bit block counter.

Block ciphers (`BlockCipher`, one block at a time):

- DES: 16-round Feistel network, 64-bit block, 56-bit effective key.
- 3DES: encrypt-decrypt-encrypt over three `DesBlockCipher` instances.
- AES-128: 10-round substitution-permutation network.

Modes of operation (`BlockMode`, over any `BlockCipher`):

- ECB and CBC, with `Pkcs7Padding` or `NoPadding`.
- CTR, OFB and CFB (full-block segments), which need no padding.
- dCTR: CTR with a fixed initial counter (1 by default) and no random nonce.

## Architecture

Everything the caller uses implements one contract:

```java
public interface Cipher {
    byte[] encrypt(byte[] plaintext);
    byte[] decrypt(byte[] ciphertext);
}
```

| Package | Responsibility |
|---------|----------------|
| `uaic.security` | The `Cipher` contract. |
| `uaic.security.classic` | The classical `CharCipher` implementations and the `TextCipherAdapter` that turns them into a `Cipher`. |
| `uaic.security.stream` | `StreamCipher`, `XorCombiner` (the only place data meets the keystream) and one `Keystream` per algorithm. |
| `uaic.security.block` | The `BlockCipher` interface; `des/` and `aes/` hold the ciphers and their primitives (tables, key schedules, round functions, GF(2^8) arithmetic). |
| `uaic.security.mode` | The six modes and the paddings. All looping, IVs, chaining and padding live here. |
| `uaic.security.util` | Byte helpers: hex, XOR, word packing and constant-time comparison. |
| `uaic.security.demo` | The command-line demo and the `CipherFactory` it uses. |

## Getting Started

### Prerequisites

- JDK 21 or higher (Gradle downloads it through the toolchain if needed).
- Gradle is optional; the `gradlew` wrapper is included.

### Building the Project

```bash
./gradlew build
```

### Running the Demo

Pass every field on the command line, in the order `<cipher> <op> <key> [iv/nonce] [mode] <input>`:

```bash
./gradlew -q --console=plain run --args="aes128 encrypt 2b7e151628aed2a6abf7158809cf4f3c 000102030405060708090a0b0c0d0e0f cbc 6bc1bee22e409f96e93d7e117393172a"
```

- `cipher`: `affine`, `substitution`, `permutation`, `transposition`, `vigenere`, `rc4`, `salsa20`, `chacha20`, `des`, `3des` or `aes128`.
- `op`: `encrypt` or `decrypt`.
- `mode` (block ciphers only): `ecb`, `cbc`, `ctr`, `dctr`, `ofb` or `cfb`. ECB and CBC use PKCS#7 padding.
- The IV is needed by `cbc`, `ctr`, `ofb` and `cfb`; the nonce by `salsa20` (8 bytes) and `chacha20` (12 bytes, block counter 1).
- Key, IV/nonce and input are hex for the byte ciphers and plain text for the classical ones. The 3DES key is the 24-byte bundle K1 | K2 | K3. The affine key is `a,b` (for example `5,8`) and the permutation key is a comma-separated permutation (for example `2,3,0,1`).

Leave out any trailing fields to be prompted for them; invalid answers are rejected with the allowed values and asked again:

```bash
./gradlew -q --console=plain run
```

An invalid command-line value prints the usage and exits with a non-zero status.

## Usage Example

```java
import uaic.security.Cipher;
import uaic.security.block.aes.Aes128BlockCipher;
import uaic.security.classic.TextCipherAdapter;
import uaic.security.classic.VigenereCipher;
import uaic.security.mode.CbcMode;
import uaic.security.mode.Pkcs7Padding;
import uaic.security.stream.ChaCha20Keystream;
import uaic.security.stream.StreamCipher;
import uaic.security.util.Bytes;

public class Example {
    public static void main(String[] args) {
        byte[] key = Bytes.fromHex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Bytes.fromHex("000102030405060708090a0b0c0d0e0f");
        Cipher aesCbc = new CbcMode(new Aes128BlockCipher(key), iv, new Pkcs7Padding());

        byte[] chachaKey = new byte[32];
        byte[] nonce = new byte[12];
        Cipher chacha = new StreamCipher(() -> new ChaCha20Keystream(chachaKey, nonce, 1));

        Cipher vigenere = new TextCipherAdapter(new VigenereCipher("KEYWORD"));

        byte[] ciphertext = aesCbc.encrypt(Bytes.fromHex("00112233445566778899aabbccddeeff"));
        byte[] plaintext = aesCbc.decrypt(ciphertext);
    }
}
```

## Testing

Run the tests:

```bash
./gradlew test
```

View the coverage report, which `test` also generates, at `lib/build/reports/jacoco/test/html/index.html`:

```bash
./gradlew jacocoTestReport
```

Every cipher has a round-trip test (`decrypt(encrypt(x)) == x`). Where a standard publishes vectors, a known-answer test (KAT) also checks the output against them. The vectors were copied from the documents below; the longer NIST files are stored as CSV under `lib/src/test/resources`.

| Cipher | Algorithm spec (vectors sourced during the step) | Link |
|--------|--------------------------------------------------|------|
| RC4 | RFC 6229 ships RC4 keystream test vectors | https://www.rfc-editor.org/info/rfc6229/ |
| Salsa20 | Bernstein spec (no full-encryption vectors); use eSTREAM/ECRYPT verified vectors | https://cr.yp.to/snuffle/spec.pdf |
| ChaCha20 | RFC 8439 §2.3.2, §2.4.2 ship vectors | https://www.rfc-editor.org/info/rfc8439 |
| DES | FIPS 46-3 (algorithm); vectors from NIST CAVP KAT files | https://csrc.nist.gov/pubs/fips/46-3/final |
| 3DES | NIST SP 800-67 Rev. 2 (algorithm); vectors from NIST CAVP | https://csrc.nist.gov/pubs/sp/800/67/r2/final |
| AES-128 | FIPS 197, Appendix B/C ship a full worked example | https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf |
| Modes (ECB/CBC/CFB/OFB/CTR) | NIST SP 800-38A Appendix F ships vectors | https://nvlpubs.nist.gov/nistpubs/Legacy/sp/nistspecialpublication800-38a.pdf |

What each KAT covers:

- **RC4**: eight RFC 6229 vectors, both key families, offsets 0, 16 and 4096.
- **Salsa20**: every example of the Bernstein specification (quarterround to the expansion function) and six keystream vectors from the ECRYPT eSTREAM `verified.test-vectors` file.
- **ChaCha20**: RFC 8439 sections 2.1.1, 2.2.1, 2.3.2 and 2.4.2 and appendix A.1 vectors 1 and 2.
- **DES**: all 235 single-DES vectors of the NIST CAVP `KAT_TDES.zip` ECB files. The key schedule is also checked against the weak, semi-weak and possibly weak keys of SP 800-67 Rev. 2.
- **3DES**: NIST CAVP `tdesmmt.zip` three-key multi-block vectors, run through ECB, CBC, OFB and CFB64.
- **AES-128**: the FIPS 197 Appendix B example, every intermediate value of Appendix A.1 and Appendix B, Tables 4 and 6, and all 284 AES-128 vectors of the NIST CAVP `KAT_AES.zip` ECB files. The 2023 update of FIPS 197 replaced the Appendix C vectors with a link to NIST's example files, so Appendix B is the worked example used.
- **Modes**: the SP 800-38A AES-128 examples F.1.1 to F.5.2 for ECB, CBC, CFB128, OFB and CTR.

Ciphers without an official vector are unit-tested only:

- **Classical ciphers** (affine, substitution, permutation, transposition, Vigenère): round-trip tests only.
- **dCTR**: no NIST vector exists; it is checked by round trip and by matching CTR started at the same fixed counter.
- **PKCS#7 padding**: checked against the padding rule of RFC 5652, section 6.3.
