package uaic.security.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import uaic.security.Cipher;
import uaic.security.util.Bytes;

class StreamCipherTest {

    private static final byte[] RC4_KEY = Bytes.fromHex("0102030405");
    private static final byte[] MESSAGE = "Attack at dawn".getBytes(StandardCharsets.UTF_8);

    /** Emits 1, 2, 3, ... from a fresh start every time it is supplied. */
    private static Keystream countingKeystream() {
        int[] nextValue = { 1 };
        return () -> (byte) nextValue[0]++;
    }

    @Test
    void encryptXorsTheMessageWithTheKeystream() {
        Cipher cipher = new StreamCipher(StreamCipherTest::countingKeystream);
        byte[] plaintext = Bytes.fromHex("000000ff");
        assertArrayEquals(Bytes.fromHex("010203fb"), cipher.encrypt(plaintext));
    }

    @Test
    void everyCallStartsAFreshKeystream() {
        Cipher cipher = new StreamCipher(StreamCipherTest::countingKeystream);
        assertArrayEquals(cipher.encrypt(MESSAGE), cipher.encrypt(MESSAGE));
    }

    @Test
    void roundTripWithRc4() {
        Cipher cipher = new StreamCipher(() -> new Rc4Keystream(RC4_KEY));
        assertArrayEquals(MESSAGE, cipher.decrypt(cipher.encrypt(MESSAGE)));
    }

    /** Encrypting zeros exposes the keystream, here the first RFC 6229 vector. */
    @Test
    void encryptingZerosWithRc4GivesTheRfc6229Keystream() {
        Cipher cipher = new StreamCipher(() -> new Rc4Keystream(RC4_KEY));
        byte[] expected = Bytes.fromHex("b2396305f03dc027ccc3524a0a1118a8");
        assertArrayEquals(expected, cipher.encrypt(new byte[expected.length]));
    }

    @Test
    void emptyMessageStaysEmpty() {
        Cipher cipher = new StreamCipher(() -> new Rc4Keystream(RC4_KEY));
        assertArrayEquals(new byte[0], cipher.encrypt(new byte[0]));
    }

    @Test
    void rejectsMissingKeystreamFactory() {
        assertThrows(NullPointerException.class, () -> new StreamCipher(null));
    }
}
