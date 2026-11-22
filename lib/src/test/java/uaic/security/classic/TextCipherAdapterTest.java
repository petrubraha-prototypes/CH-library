package uaic.security.classic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import uaic.security.Cipher;

class TextCipherAdapterTest {

    /** No spaces: PermutationCipher drops spaces, a known limitation of its padding. */
    private static final String MESSAGE = "AttackAtDawn2026";

    /** Reverses the text, so encryption and decryption are easy to predict. */
    private static final CharCipher REVERSING_CIPHER = new CharCipher() {
        @Override
        public String encrypt(String plaintext) {
            return new StringBuilder(plaintext).reverse().toString();
        }

        @Override
        public String decrypt(String ciphertext) {
            return new StringBuilder(ciphertext).reverse().toString();
        }
    };

    private static Stream<CharCipher> classicalCiphers() {
        return Stream.of(
                new AffineCipher(5, 8),
                new SubstitutionCipher("qwertyuiopasdfghjklzxcvbnm"),
                new PermutationCipher(new int[] { 2, 3, 0, 1 }),
                new TranspositionCipher("SECRET"),
                new VigenereCipher("KEYWORD"));
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void encryptPassesTheDecodedTextToTheCharCipher() {
        Cipher adapter = new TextCipherAdapter(REVERSING_CIPHER);
        assertArrayEquals(utf8("cba"), adapter.encrypt(utf8("abc")));
    }

    @Test
    void decryptPassesTheDecodedTextToTheCharCipher() {
        Cipher adapter = new TextCipherAdapter(REVERSING_CIPHER);
        assertArrayEquals(utf8("abc"), adapter.decrypt(utf8("cba")));
    }

    @Test
    void encryptMatchesTheUnderlyingCharCipher() {
        CharCipher vigenere = new VigenereCipher("KEYWORD");
        Cipher adapter = new TextCipherAdapter(vigenere);
        String ciphertext = new String(adapter.encrypt(utf8(MESSAGE)), StandardCharsets.UTF_8);
        assertEquals(vigenere.encrypt(MESSAGE), ciphertext);
    }

    @Test
    void multiByteCharactersSurviveTheByteBoundary() {
        Cipher adapter = new TextCipherAdapter(REVERSING_CIPHER);
        String text = "ÄƒÃ®È™È›Ã¢";
        assertArrayEquals(utf8(text), adapter.decrypt(adapter.encrypt(utf8(text))));
    }

    @Test
    void rejectsMissingCharCipher() {
        assertThrows(NullPointerException.class, () -> new TextCipherAdapter(null));
    }

    @ParameterizedTest
    @MethodSource("classicalCiphers")
    void roundTripThroughEachClassicalCipher(CharCipher charCipher) {
        Cipher adapter = new TextCipherAdapter(charCipher);
        byte[] plaintext = utf8(MESSAGE);
        assertArrayEquals(plaintext, adapter.decrypt(adapter.encrypt(plaintext)));
    }
}
