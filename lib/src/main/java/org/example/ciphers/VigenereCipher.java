package org.example.ciphers;

import org.example.util.AlphabetUtils;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Vigenere Cipher implementation.
 * A polyalphabetic substitution cipher based on a keyword.
 */
@RequiredArgsConstructor
public class VigenereCipher implements Cipher {
    @NonNull
    private final String key;

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null || key == null || key.isEmpty())
            return plaintext;

        StringBuilder sb = new StringBuilder();
        int keyIndex = 0;

        for (char c : plaintext.toCharArray()) {
            int pIdx = AlphabetUtils.charToIndex(c);
            if (pIdx == -1) {
                sb.append(c);
            } else {
                int kIdx = AlphabetUtils.charToIndex(key.charAt(keyIndex % key.length()));
                if (kIdx == -1) {
                    // For simplicity, we'll increment keyIndex only on successful mapping.
                    sb.append(c);
                    continue;
                }
                int encrypted = (pIdx + kIdx) % AlphabetUtils.ALPHABET_SIZE;
                sb.append(AlphabetUtils.indexToChar(encrypted, Character.isUpperCase(c)));
                keyIndex++;
            }
        }
        return sb.toString();
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null || key == null || key.isEmpty())
            return ciphertext;

        StringBuilder sb = new StringBuilder();
        int keyIndex = 0;

        for (char c : ciphertext.toCharArray()) {
            int cIdx = AlphabetUtils.charToIndex(c);
            if (cIdx == -1) {
                sb.append(c);
            } else {
                int kIdx = AlphabetUtils.charToIndex(key.charAt(keyIndex % key.length()));
                if (kIdx == -1) {
                    sb.append(c);
                    continue;
                }
                int decrypted = (cIdx - kIdx) % AlphabetUtils.ALPHABET_SIZE;
                if (decrypted < 0)
                    decrypted += AlphabetUtils.ALPHABET_SIZE;
                sb.append(AlphabetUtils.indexToChar(decrypted, Character.isUpperCase(c)));
                keyIndex++;
            }
        }
        return sb.toString();
    }
}
