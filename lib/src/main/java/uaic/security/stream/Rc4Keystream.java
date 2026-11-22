package uaic.security.stream;

/**
 * Generates the RC4 keystream: the key-scheduling algorithm (KSA) builds a
 * permutation of the 256 byte values from the key, then the pseudo-random
 * generation algorithm (PRGA) keeps swapping its entries and emits one of
 * them per byte.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> RC4 has known
 * keystream biases and is prohibited in TLS.
 */
public class Rc4Keystream implements Keystream {
    private static final int STATE_SIZE = 256;
    private static final int MINIMUM_KEY_LENGTH = 1;
    private static final int MAXIMUM_KEY_LENGTH = 256;
    private static final int BYTE_MASK = 0xFF;

    /** The state S: a permutation of 0..255. */
    private final int[] permutation = new int[STATE_SIZE];
    /** The PRGA index i, advanced by one per output byte. */
    private int stepIndex;
    /** The PRGA index j, moved by the state itself. */
    private int mixIndex;

    /**
     * Runs the key-scheduling algorithm.
     *
     * @param key between 1 and 256 bytes
     * @throws IllegalArgumentException if the key length is out of range
     */
    public Rc4Keystream(byte[] key) {
        validateKeyLength(key);
        scheduleKey(key);
    }

    private static void validateKeyLength(byte[] key) {
        if (key.length < MINIMUM_KEY_LENGTH || key.length > MAXIMUM_KEY_LENGTH) {
            throw new IllegalArgumentException("RC4 key must be between " + MINIMUM_KEY_LENGTH + " and "
                    + MAXIMUM_KEY_LENGTH + " bytes, got " + key.length);
        }
    }

    /** KSA: starts from the identity permutation and swaps entries driven by the key. */
    private void scheduleKey(byte[] key) {
        for (int value = 0; value < STATE_SIZE; value++) {
            permutation[value] = value;
        }
        int keyMixIndex = 0;
        for (int index = 0; index < STATE_SIZE; index++) {
            int keyByte = key[index % key.length] & BYTE_MASK;
            keyMixIndex = (keyMixIndex + permutation[index] + keyByte) % STATE_SIZE;
            swap(index, keyMixIndex);
        }
    }

    /** PRGA: one swap per output byte, then outputs S[S[i] + S[j]]. */
    @Override
    public byte nextByte() {
        stepIndex = (stepIndex + 1) % STATE_SIZE;
        mixIndex = (mixIndex + permutation[stepIndex]) % STATE_SIZE;
        swap(stepIndex, mixIndex);
        int outputIndex = (permutation[stepIndex] + permutation[mixIndex]) % STATE_SIZE;
        return (byte) permutation[outputIndex];
    }

    private void swap(int firstIndex, int secondIndex) {
        int firstValue = permutation[firstIndex];
        permutation[firstIndex] = permutation[secondIndex];
        permutation[secondIndex] = firstValue;
    }
}
