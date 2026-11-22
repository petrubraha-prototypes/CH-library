package uaic.security.mode;

/**
 * The null-object {@link Padding}: leaves the data unchanged, for messages
 * that the caller guarantees already fill whole blocks.
 *
 * <p>
 * The mode still rejects data that does not split into whole blocks.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class NoPadding implements Padding {
    @Override
    public byte[] pad(byte[] data, int blockSize) {
        return data.clone();
    }

    @Override
    public byte[] unpad(byte[] paddedData, int blockSize) {
        return paddedData.clone();
    }
}
