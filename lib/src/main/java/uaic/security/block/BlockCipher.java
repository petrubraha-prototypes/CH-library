package uaic.security.block;

/**
 * Transforms exactly one fixed-size block under a key fixed at construction.
 *
 * <p>
 * It never loops over a message, never sees an IV and never pads: those are
 * the job of a {@code BlockMode} and a {@code Padding}.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public interface BlockCipher {
    /**
     * Returns the block length in bytes.
     *
     * @return the number of bytes in one block
     */
    int blockSize();

    /**
     * Encrypts a single block.
     *
     * @param plaintextBlock exactly {@link #blockSize()} bytes
     * @return the encrypted block, of the same length
     */
    byte[] encryptBlock(byte[] plaintextBlock);

    /**
     * Decrypts a single block.
     *
     * @param ciphertextBlock exactly {@link #blockSize()} bytes
     * @return the decrypted block, of the same length
     */
    byte[] decryptBlock(byte[] ciphertextBlock);
}
