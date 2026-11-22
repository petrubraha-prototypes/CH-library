package uaic.security.block.des;

import uaic.security.util.Bytes;

/**
 * Derives the sixteen 48-bit DES subkeys K1 to K16 from a 64-bit key (FIPS
 * 46-3, key schedule calculation): PC-1 drops the parity bits and splits the
 * rest into the 28-bit halves C0 and D0, each round rotates both halves left
 * and PC-2 picks 48 of their 56 bits.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> The effective
 * key is only 56 bits.
 */
class DesKeySchedule {
    static final int ROUNDS = 16;

    private static final int KEY_BITS = 64;
    private static final int PERMUTED_KEY_BITS = 56;
    private static final int HALF_BITS = 28;
    private static final long HALF_MASK = (1L << HALF_BITS) - 1;

    private final long[] subkeys = new long[ROUNDS];

    /**
     * @param key 8 bytes; the lowest bit of each byte is a parity bit and is ignored
     * @throws IllegalArgumentException if the key is not 8 bytes
     */
    DesKeySchedule(byte[] key) {
        if (key.length != Long.BYTES) {
            throw new IllegalArgumentException("DES key must be " + Long.BYTES + " bytes, got " + key.length);
        }
        long keyBits = Bytes.toLongBigEndian(key);
        long permutedKey = DesPermutation.apply(keyBits, KEY_BITS, DesTables.PERMUTED_CHOICE_1);
        long leftHalf = permutedKey >>> HALF_BITS;
        long rightHalf = permutedKey & HALF_MASK;
        for (int round = 0; round < ROUNDS; round++) {
            int shift = DesTables.LEFT_SHIFTS[round];
            leftHalf = rotateHalfLeft(leftHalf, shift);
            rightHalf = rotateHalfLeft(rightHalf, shift);
            long joinedHalves = (leftHalf << HALF_BITS) | rightHalf;
            subkeys[round] = DesPermutation.apply(joinedHalves, PERMUTED_KEY_BITS, DesTables.PERMUTED_CHOICE_2);
        }
    }

    /**
     * Returns the subkey of one round.
     *
     * @param roundNumber 1 to 16, as Kn is numbered in FIPS 46-3
     * @return the 48-bit subkey, right-aligned
     */
    long subkey(int roundNumber) {
        if (roundNumber < 1 || roundNumber > ROUNDS) {
            throw new IllegalArgumentException("DES round number must be between 1 and " + ROUNDS
                    + ", got " + roundNumber);
        }
        return subkeys[roundNumber - 1];
    }

    private static long rotateHalfLeft(long half, int shift) {
        long rotated = (half << shift) | (half >>> (HALF_BITS - shift));
        return rotated & HALF_MASK;
    }
}
