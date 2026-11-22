package uaic.security.block.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Examples from FIPS 197 (2023 update), section 4. */
class AesGaloisFieldTest {

    /** Eq. 4.6: repeated XTIMES() of {57}. */
    @ParameterizedTest
    @CsvSource({ "57, ae", "ae, 47", "47, 8e", "8e, 07", "07, 0e", "0e, 1c", "1c, 38" })
    void xtimeMatchesTheSpecification(String inputHex, String expectedHex) {
        assertEquals(Integer.parseInt(expectedHex, 16), AesGaloisField.xtime(Integer.parseInt(inputHex, 16)));
    }

    /** Eq. 4.7: {57} * {13} = {fe}. */
    @Test
    void multiplyMatchesTheSpecification() {
        assertEquals(0xfe, AesGaloisField.multiply(0x57, 0x13));
    }

    /** Eq. 4.6 again, through multiply: {57} * {80} = {38}. */
    @Test
    void multiplyByAPowerOfTwoRepeatsXtime() {
        assertEquals(0x38, AesGaloisField.multiply(0x57, 0x80));
    }

    @Test
    void multiplyIsCommutative() {
        for (int left = 0; left < 256; left += 17) {
            for (int right = 0; right < 256; right += 13) {
                assertEquals(AesGaloisField.multiply(left, right), AesGaloisField.multiply(right, left));
            }
        }
    }

    /** Eq. 4.10: b * b^-1 = {01} for every non-zero b. */
    @Test
    void inverseTimesValueIsOne() {
        for (int value = 1; value < 256; value++) {
            assertEquals(0x01, AesGaloisField.multiply(value, AesGaloisField.inverse(value)));
        }
    }

    @Test
    void inverseOfZeroIsZero() {
        assertEquals(0x00, AesGaloisField.inverse(0x00));
    }
}
