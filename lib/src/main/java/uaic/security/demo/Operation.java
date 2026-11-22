package uaic.security.demo;

import java.util.function.BiFunction;

import lombok.RequiredArgsConstructor;
import uaic.security.Cipher;

/**
 * The two operations a demo user can run on the configured cipher.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@RequiredArgsConstructor
enum Operation implements Choice {
    ENCRYPT("encrypt", Cipher::encrypt),
    DECRYPT("decrypt", Cipher::decrypt);

    private final String label;
    private final BiFunction<Cipher, byte[], byte[]> action;

    @Override
    public String label() {
        return label;
    }

    /**
     * Runs this operation.
     *
     * @param cipher the configured cipher
     * @param data   the plaintext or ciphertext
     * @return the result of the operation
     */
    byte[] apply(Cipher cipher, byte[] data) {
        return action.apply(cipher, data);
    }
}
