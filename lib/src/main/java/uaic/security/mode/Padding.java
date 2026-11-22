package uaic.security.mode;

/**
 * Extends a message to a whole number of blocks and strips that extension
 * again; it knows nothing about chaining.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public interface Padding {
    /**
     * Pads the data to a multiple of the block size.
     *
     * @param data      the unpadded message
     * @param blockSize the block length in bytes
     * @return a new array whose length is a multiple of {@code blockSize}
     */
    byte[] pad(byte[] data, int blockSize);

    /**
     * Removes the padding added by {@link #pad(byte[], int)}.
     *
     * @param paddedData a message whose length is a multiple of
     *                   {@code blockSize}
     * @param blockSize  the block length in bytes
     * @return a new array holding the original message
     */
    byte[] unpad(byte[] paddedData, int blockSize);
}
