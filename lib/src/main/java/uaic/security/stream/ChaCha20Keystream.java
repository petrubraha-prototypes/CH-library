package uaic.security.stream;

import uaic.security.util.Bytes;

/**
 * Generates the ChaCha20 keystream as defined in RFC 8439, section 2: block
 * {@code i} is the ChaCha20 block function of the key, the 96-bit nonce and
 * the 32-bit block counter {@code initialCounter + i}.
 *
 * <p>
 * ChaCha20 refines Salsa20: the same ARX building blocks, but a quarter round
 * that mixes every word twice and rounds that alternate between the columns
 * and the diagonals of the 4x4 state.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> The counter is
 * 32 bits, so one key and nonce pair covers at most 2^32 blocks (256 GB).
 */
public class ChaCha20Keystream extends CounterBlockKeystream {
    private static final int KEY_LENGTH = 32;
    private static final int NONCE_LENGTH = 12;
    private static final int DOUBLE_ROUNDS = 10;

    /** Section 2.3: words 0-3 of the state. */
    private static final int[] CONSTANTS = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    private static final int FIRST_ROTATION = 16;
    private static final int SECOND_ROTATION = 12;
    private static final int THIRD_ROTATION = 8;
    private static final int FOURTH_ROTATION = 7;

    /** Section 2.3: quarter rounds 1-4 work on the columns of the state. */
    private static final int[][] COLUMN_ROUND_POSITIONS = {
            { 0, 4, 8, 12 }, { 1, 5, 9, 13 }, { 2, 6, 10, 14 }, { 3, 7, 11, 15 } };

    /** Section 2.3: quarter rounds 5-8 work on the diagonals of the state. */
    private static final int[][] DIAGONAL_ROUND_POSITIONS = {
            { 0, 5, 10, 15 }, { 1, 6, 11, 12 }, { 2, 7, 8, 13 }, { 3, 4, 9, 14 } };

    private final int[] keyWords;
    private final int[] nonceWords;

    /**
     * @param key            32 bytes
     * @param nonce          12 bytes, unique per message under the same key
     * @param initialCounter the block counter of the first block, read as an
     *                       unsigned 32-bit value (usually 0 or 1)
     * @throws IllegalArgumentException if a length is not supported
     */
    public ChaCha20Keystream(byte[] key, byte[] nonce, int initialCounter) {
        super(Integer.toUnsignedLong(initialCounter));
        validateLengths(key, nonce);
        this.keyWords = Bytes.toIntsLittleEndian(key);
        this.nonceWords = Bytes.toIntsLittleEndian(nonce);
    }

    private static void validateLengths(byte[] key, byte[] nonce) {
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "ChaCha20 key must be " + KEY_LENGTH + " bytes, got " + key.length);
        }
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "ChaCha20 nonce must be " + NONCE_LENGTH + " bytes, got " + nonce.length);
        }
    }

    /** Section 2.3.1: chacha20_block(key, counter, nonce). */
    @Override
    protected byte[] generateBlock(long blockCounter) {
        int[] initialState = initialState((int) blockCounter);
        int[] state = initialState.clone();
        for (int round = 0; round < DOUBLE_ROUNDS; round++) {
            innerBlock(state);
        }
        for (int index = 0; index < state.length; index++) {
            state[index] += initialState[index];
        }
        return Bytes.fromIntsLittleEndian(state);
    }

    /** Section 2.3: constants | key | counter | nonce. */
    private int[] initialState(int blockCounter) {
        return new int[] {
                CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
                keyWords[0], keyWords[1], keyWords[2], keyWords[3],
                keyWords[4], keyWords[5], keyWords[6], keyWords[7],
                blockCounter, nonceWords[0], nonceWords[1], nonceWords[2] };
    }

    /** Section 2.3.1: one column round followed by one diagonal round. */
    private static void innerBlock(int[] state) {
        for (int[] positions : COLUMN_ROUND_POSITIONS) {
            quarterRound(state, positions);
        }
        for (int[] positions : DIAGONAL_ROUND_POSITIONS) {
            quarterRound(state, positions);
        }
    }

    /**
     * Sections 2.1 and 2.2: QUARTERROUND on the state words at
     * {@code positions} (a, b, c, d), in place.
     */
    static void quarterRound(int[] state, int[] positions) {
        int a = state[positions[0]];
        int b = state[positions[1]];
        int c = state[positions[2]];
        int d = state[positions[3]];
        a += b;
        d = Integer.rotateLeft(d ^ a, FIRST_ROTATION);
        c += d;
        b = Integer.rotateLeft(b ^ c, SECOND_ROTATION);
        a += b;
        d = Integer.rotateLeft(d ^ a, THIRD_ROTATION);
        c += d;
        b = Integer.rotateLeft(b ^ c, FOURTH_ROTATION);
        state[positions[0]] = a;
        state[positions[1]] = b;
        state[positions[2]] = c;
        state[positions[3]] = d;
    }
}
