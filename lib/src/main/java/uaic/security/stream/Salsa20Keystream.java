package uaic.security.stream;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import uaic.security.util.Bytes;

/**
 * Generates the Salsa20/20 keystream as defined in Bernstein's "Salsa20
 * specification": block {@code i} is the Salsa20 hash of the constants, the
 * key, the 8-byte nonce and the 64-bit block number {@code i}.
 *
 * <p>
 * The hash is built only from 32-bit additions, rotations and XORs (ARX):
 * quarterround, then rowround and columnround, then ten doublerounds, then
 * the input is added back to the output.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class Salsa20Keystream extends CounterBlockKeystream {
    private static final int NONCE_LENGTH = 8;
    private static final int SHORT_KEY_LENGTH = 16;
    private static final int LONG_KEY_LENGTH = 32;

    private static final int DOUBLE_ROUNDS = 10;
    private static final int FIRST_INITIAL_COUNTER = 0;

    /** ASCII "expand 32-byte k" and "expand 16-byte k", section 9 of the specification. */
    private static final int[] SIGMA = constantWords("expand 32-byte k");
    private static final int[] TAU = constantWords("expand 16-byte k");

    private static final int FIRST_ROTATION = 7;
    private static final int SECOND_ROTATION = 9;
    private static final int THIRD_ROTATION = 13;
    private static final int FOURTH_ROTATION = 18;

    /** The four quarterround inputs of rowround, section 4: each row, rotated. */
    private static final int[][] ROW_ROUND_POSITIONS = {
            { 0, 1, 2, 3 }, { 5, 6, 7, 4 }, { 10, 11, 8, 9 }, { 15, 12, 13, 14 } };

    /** The four quarterround inputs of columnround, section 5: each column, rotated. */
    private static final int[][] COLUMN_ROUND_POSITIONS = {
            { 0, 4, 8, 12 }, { 5, 9, 13, 1 }, { 10, 14, 2, 6 }, { 15, 3, 7, 11 } };

    private final byte[] key;
    private final byte[] nonce;

    /**
     * @param key   16 or 32 bytes
     * @param nonce 8 bytes, unique per message under the same key
     * @throws IllegalArgumentException if a length is not supported
     */
    public Salsa20Keystream(byte[] key, byte[] nonce) {
        super(FIRST_INITIAL_COUNTER);
        validateLengths(key, nonce);
        this.key = key.clone();
        this.nonce = nonce.clone();
    }

    private static void validateLengths(byte[] key, byte[] nonce) {
        if (key.length != SHORT_KEY_LENGTH && key.length != LONG_KEY_LENGTH) {
            throw new IllegalArgumentException("Salsa20 key must be " + SHORT_KEY_LENGTH + " or "
                    + LONG_KEY_LENGTH + " bytes, got " + key.length);
        }
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException(
                    "Salsa20 nonce must be " + NONCE_LENGTH + " bytes, got " + nonce.length);
        }
    }

    private static int[] constantWords(String asciiConstant) {
        byte[] constantBytes = asciiConstant.getBytes(StandardCharsets.US_ASCII);
        return Bytes.toIntsLittleEndian(constantBytes);
    }

    /** Section 10: block i is Salsa20_k(nonce, littleendian64(i)). */
    @Override
    protected byte[] generateBlock(long blockCounter) {
        byte[] nonceAndCounter = new byte[NONCE_LENGTH + Long.BYTES];
        System.arraycopy(nonce, 0, nonceAndCounter, 0, NONCE_LENGTH);
        Bytes.writeIntLittleEndian((int) blockCounter, nonceAndCounter, NONCE_LENGTH);
        Bytes.writeIntLittleEndian((int) (blockCounter >>> Integer.SIZE), nonceAndCounter,
                NONCE_LENGTH + Integer.BYTES);
        return expand(key, nonceAndCounter);
    }

    /**
     * The Salsa20 expansion function, section 9: lays out the constants, the
     * key and the 16-byte input as (c0, k0, c1, n, c2, k1, c3) and hashes it.
     * A 16-byte key is used twice with the "16-byte" constants.
     */
    static byte[] expand(byte[] key, byte[] sixteenByteInput) {
        boolean isLongKey = key.length == LONG_KEY_LENGTH;
        int[] constants = isLongKey ? SIGMA : TAU;
        byte[] firstKeyHalf = Arrays.copyOfRange(key, 0, SHORT_KEY_LENGTH);
        byte[] secondKeyHalf = isLongKey
                ? Arrays.copyOfRange(key, SHORT_KEY_LENGTH, LONG_KEY_LENGTH)
                : firstKeyHalf;
        int[] k0 = Bytes.toIntsLittleEndian(firstKeyHalf);
        int[] k1 = Bytes.toIntsLittleEndian(secondKeyHalf);
        int[] n = Bytes.toIntsLittleEndian(sixteenByteInput);
        int[] state = {
                constants[0], k0[0], k0[1], k0[2],
                k0[3], constants[1], n[0], n[1],
                n[2], n[3], constants[2], k1[0],
                k1[1], k1[2], k1[3], constants[3] };
        return hash(Bytes.fromIntsLittleEndian(state));
    }

    /** The Salsa20 hash function, section 8: x + doubleround^10(x), word by word. */
    static byte[] hash(byte[] input) {
        int[] originalWords = Bytes.toIntsLittleEndian(input);
        int[] state = originalWords.clone();
        for (int round = 0; round < DOUBLE_ROUNDS; round++) {
            doubleRound(state);
        }
        for (int index = 0; index < state.length; index++) {
            state[index] += originalWords[index];
        }
        return Bytes.fromIntsLittleEndian(state);
    }

    /** Section 6: a columnround followed by a rowround. */
    static void doubleRound(int[] state) {
        columnRound(state);
        rowRound(state);
    }

    /** Section 4: quarterround on each row of the 4x4 matrix, in place. */
    static void rowRound(int[] state) {
        for (int[] positions : ROW_ROUND_POSITIONS) {
            quarterRound(state, positions);
        }
    }

    /** Section 5: quarterround on each column of the 4x4 matrix, in place. */
    static void columnRound(int[] state) {
        for (int[] positions : COLUMN_ROUND_POSITIONS) {
            quarterRound(state, positions);
        }
    }

    /**
     * Section 3: updates the words at {@code positions} (y0, y1, y2, y3) in
     * place, in the order y1, y2, y3, y0.
     */
    static void quarterRound(int[] state, int[] positions) {
        int y0 = state[positions[0]];
        int y1 = state[positions[1]];
        int y2 = state[positions[2]];
        int y3 = state[positions[3]];
        int z1 = y1 ^ Integer.rotateLeft(y0 + y3, FIRST_ROTATION);
        int z2 = y2 ^ Integer.rotateLeft(z1 + y0, SECOND_ROTATION);
        int z3 = y3 ^ Integer.rotateLeft(z2 + z1, THIRD_ROTATION);
        int z0 = y0 ^ Integer.rotateLeft(z3 + z2, FOURTH_ROTATION);
        state[positions[0]] = z0;
        state[positions[1]] = z1;
        state[positions[2]] = z2;
        state[positions[3]] = z3;
    }
}
