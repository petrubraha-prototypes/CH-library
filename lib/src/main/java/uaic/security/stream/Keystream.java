package uaic.security.stream;

/**
 * Generates a pseudo-random byte sequence from a key; it never touches the
 * message.
 *
 * <p>
 * Each instance is a single-use generator: every call continues the sequence
 * where the previous call stopped.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public interface Keystream {
    /**
     * Produces the next keystream byte.
     *
     * @return the next byte of the sequence
     */
    byte nextByte();

    /**
     * Overwrites every byte of the destination with the next keystream bytes.
     *
     * @param destination the array to fill, from index zero
     */
    default void fill(byte[] destination) {
        for (int index = 0; index < destination.length; index++) {
            destination[index] = nextByte();
        }
    }
}
