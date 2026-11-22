package uaic.security.mode;

import uaic.security.block.BlockCipher;
import uaic.security.block.aes.Aes128BlockCipher;
import uaic.security.util.Bytes;

/**
 * The key and the four-block plaintext shared by every AES-128 example of
 * NIST SP 800-38A, Appendix F.
 */
final class Sp80038aVectors {
    static final byte[] PLAINTEXT = Bytes.fromHex("6bc1bee22e409f96e93d7e117393172a"
            + "ae2d8a571e03ac9c9eb76fac45af8e51"
            + "30c81c46a35ce411e5fbc1191a0a52ef"
            + "f69f2445df4f9b17ad2b417be66c3710");

    /** The IV of the CBC, CFB and OFB examples. */
    static final byte[] INITIALIZATION_VECTOR = Bytes.fromHex("000102030405060708090a0b0c0d0e0f");

    private static final byte[] KEY = Bytes.fromHex("2b7e151628aed2a6abf7158809cf4f3c");

    private Sp80038aVectors() {
    }

    static BlockCipher aes128() {
        return new Aes128BlockCipher(KEY);
    }
}
