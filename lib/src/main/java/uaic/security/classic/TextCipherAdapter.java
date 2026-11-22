package uaic.security.classic;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import uaic.security.Cipher;

/**
 * Exposes a character-level {@link CharCipher} as a byte-level
 * {@link Cipher}: decodes the input bytes as UTF-8 text, lets the classical
 * cipher work on the characters and encodes the result back to UTF-8.
 *
 * <p>
 * This is the only class in which classical ciphers cross the byte boundary.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@RequiredArgsConstructor
public class TextCipherAdapter implements Cipher {
    private static final Charset TEXT_ENCODING = StandardCharsets.UTF_8;

    @NonNull
    private final CharCipher charCipher;

    @Override
    public byte[] encrypt(byte[] plaintext) {
        String plaintextText = new String(plaintext, TEXT_ENCODING);
        String ciphertextText = charCipher.encrypt(plaintextText);
        return ciphertextText.getBytes(TEXT_ENCODING);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        String ciphertextText = new String(ciphertext, TEXT_ENCODING);
        String plaintextText = charCipher.decrypt(ciphertextText);
        return plaintextText.getBytes(TEXT_ENCODING);
    }
}
