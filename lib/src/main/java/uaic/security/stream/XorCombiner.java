package uaic.security.stream;

import lombok.experimental.UtilityClass;
import uaic.security.util.Bytes;

/**
 * The single place where stream cipher data meets the keystream: XORs each
 * data byte with the next keystream byte.
 *
 * <p>
 * Because XOR is its own inverse, the same combination encrypts and decrypts.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
public class XorCombiner {
    /**
     * XORs the data with as many keystream bytes as the data is long.
     *
     * @param data      the plaintext or ciphertext
     * @param keystream the generator the bytes are drawn from
     * @return a new array holding {@code data XOR keystream}
     */
    public static byte[] combine(byte[] data, Keystream keystream) {
        byte[] keystreamBytes = new byte[data.length];
        keystream.fill(keystreamBytes);
        return Bytes.xor(data, keystreamBytes);
    }
}
