package uaic.security.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import uaic.security.Cipher;
import uaic.security.util.Bytes;

/** Known-answer vectors from RFC 8439, sections 2.1.1 to 2.4.2 and appendix A.1. */
class ChaCha20KeystreamTest {

    private static final int BLOCK_LENGTH = 64;
    private static final byte[] RFC_KEY = Bytes.fromHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] ZERO_KEY = new byte[32];
    private static final byte[] ZERO_NONCE = new byte[12];

    private static byte[] firstBytes(Keystream keystream, int length) {
        byte[] output = new byte[length];
        keystream.fill(output);
        return output;
    }

    /** Section 2.1.1. */
    @Test
    void quarterRoundMatchesRfc8439() {
        int[] state = { 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567 };
        ChaCha20Keystream.quarterRound(state, new int[] { 0, 1, 2, 3 });
        assertArrayEquals(new int[] { 0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb }, state);
    }

    /** Section 2.2.1: QUARTERROUND(2, 7, 8, 13) changes only those four words. */
    @Test
    void quarterRoundOnTheStateMatchesRfc8439() {
        int[] state = {
                0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320 };
        int[] expected = {
                0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320 };
        ChaCha20Keystream.quarterRound(state, new int[] { 2, 7, 8, 13 });
        assertArrayEquals(expected, state);
    }

    /** Section 2.3.2: the serialized block for block count 1. */
    @Test
    void blockFunctionMatchesRfc8439() {
        byte[] nonce = Bytes.fromHex("000000090000004a00000000");
        Keystream keystream = new ChaCha20Keystream(RFC_KEY, nonce, 1);
        byte[] expected = Bytes.fromHex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                + "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
        assertArrayEquals(expected, firstBytes(keystream, BLOCK_LENGTH));
    }

    /** Appendix A.1, test vectors 1 and 2: all-zero key and nonce. */
    @ParameterizedTest
    @CsvSource({
            "0, 76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    + "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            "1, 9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
                    + "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f",
    })
    void zeroKeyBlocksMatchRfc8439(int blockCounter, String expectedHex) {
        Keystream keystream = new ChaCha20Keystream(ZERO_KEY, ZERO_NONCE, blockCounter);
        assertArrayEquals(Bytes.fromHex(expectedHex), firstBytes(keystream, BLOCK_LENGTH));
    }

    /** Section 2.4.2: the "sunscreen" message spans two blocks and a partial third. */
    @Test
    void encryptionMatchesRfc8439() {
        byte[] nonce = Bytes.fromHex("000000000000004a00000000");
        Cipher cipher = new StreamCipher(() -> new ChaCha20Keystream(RFC_KEY, nonce, 1));
        byte[] plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip"
                + " for the future, sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
        byte[] expected = Bytes.fromHex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                + "5af90bbf74a35be6b40b8eedf2785e42874d");
        assertArrayEquals(expected, cipher.encrypt(plaintext));
        assertArrayEquals(plaintext, cipher.decrypt(expected));
    }

    @Test
    void rejectsUnsupportedKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new ChaCha20Keystream(new byte[16], ZERO_NONCE, 0));
    }

    @Test
    void rejectsUnsupportedNonceLength() {
        assertThrows(IllegalArgumentException.class, () -> new ChaCha20Keystream(ZERO_KEY, new byte[8], 0));
    }
}
