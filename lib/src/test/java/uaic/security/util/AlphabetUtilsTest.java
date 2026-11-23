package uaic.security.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AlphabetUtilsTest {

    @ParameterizedTest
    @CsvSource({ "5, 26, 21", "1, 26, 1", "25, 26, 25", "-5, 26, 5" })
    void modInverseTimesValueIsOne(int value, int modulus, int expectedInverse) {
        assertEquals(expectedInverse, AlphabetUtils.modInverse(value, modulus));
    }

    @Test
    void modInverseRejectsValuesThatShareAFactorWithTheModulus() {
        assertThrows(IllegalArgumentException.class, () -> AlphabetUtils.modInverse(2, 26));
    }

    @ParameterizedTest
    @CsvSource({ "a, 0", "Z, 25", "m, 12" })
    void charToIndexIgnoresCase(char letter, int expectedIndex) {
        assertEquals(expectedIndex, AlphabetUtils.charToIndex(letter));
    }

    @Test
    void charToIndexReturnsMinusOneForNonLetters() {
        assertEquals(-1, AlphabetUtils.charToIndex('7'));
    }

    @Test
    void indexToCharKeepsTheRequestedCase() {
        assertEquals('c', AlphabetUtils.indexToChar(2, false));
        assertEquals('C', AlphabetUtils.indexToChar(2, true));
    }

    @Test
    void indexToCharWrapsAroundTheAlphabet() {
        assertEquals('b', AlphabetUtils.indexToChar(27, false));
        assertEquals('z', AlphabetUtils.indexToChar(-1, false));
    }
}
