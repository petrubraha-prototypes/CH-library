package uaic.security.block.aes;

import lombok.experimental.UtilityClass;

/**
 * Arithmetic in the AES finite field GF(2^8) (FIPS 197, sections 4.1 to
 * 4.4): bytes are polynomials over GF(2) reduced modulo
 * {@code m(x) = x^8 + x^4 + x^3 + x + 1}. Addition is XOR; this class
 * provides multiplication and the multiplicative inverse.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> The running
 * time depends on the operands.
 */
@UtilityClass
class AesGaloisField {
    private static final int BYTE_MASK = 0xFF;
    private static final int HIGH_BIT = 0x80;
    /** The low byte of m(x): {00011011}. */
    private static final int REDUCTION_BYTE = 0x1B;
    /** Eq. 4.11: the inverse of b is b^254. */
    private static final int INVERSE_EXPONENT = 254;
    private static final int ONE = 0x01;

    /**
     * XTIMES(b), Eq. 4.5: multiplies by {02}, that is by x, reducing modulo m(x).
     *
     * @param value a byte, 0 to 255
     * @return {@code value * {02}}
     */
    static int xtime(int value) {
        int shifted = (value << 1) & BYTE_MASK;
        boolean overflows = (value & HIGH_BIT) != 0;
        return overflows ? shifted ^ REDUCTION_BYTE : shifted;
    }

    /**
     * Multiplies two field elements by adding up {@code left * x^i} for every
     * set bit {@code i} of {@code right}, as in Eq. 4.7.
     *
     * @param left  a byte, 0 to 255
     * @param right a byte, 0 to 255
     * @return the product in GF(2^8)
     */
    static int multiply(int left, int right) {
        int product = 0;
        int multipleOfLeft = left;
        for (int remainingBits = right; remainingBits != 0; remainingBits >>>= 1) {
            if ((remainingBits & ONE) != 0) {
                product ^= multipleOfLeft;
            }
            multipleOfLeft = xtime(multipleOfLeft);
        }
        return product;
    }

    /**
     * The multiplicative inverse, Eq. 4.11: {@code b^-1 = b^254}. By the same
     * formula {00} maps to {00}, as SBOX() requires.
     *
     * @param value a byte, 0 to 255
     * @return {@code value^254}
     */
    static int inverse(int value) {
        int power = ONE;
        for (int exponent = 0; exponent < INVERSE_EXPONENT; exponent++) {
            power = multiply(power, value);
        }
        return power;
    }
}
