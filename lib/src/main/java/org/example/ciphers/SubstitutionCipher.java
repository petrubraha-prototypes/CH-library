package org.example.ciphers;

import org.example.util.AlphabetUtils;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Monoalphabetic substitution cipher.
 * Maps each alphabet character to its permutated counterpart.
 */
@RequiredArgsConstructor
public class SubstitutionCipher implements Cipher {
    @NonNull
    private final String permutatedAlphabet;

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null)
            return null;
        if (permutatedAlphabet.length() < AlphabetUtils.ALPHABET_SIZE) {
            throw new IllegalArgumentException(
                    "Permutated alphabet must have " + AlphabetUtils.ALPHABET_SIZE + " characters.");
        }

        StringBuilder sb = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            int index = AlphabetUtils.charToIndex(c);
            if (index == -1) {
                sb.append(c);
            } else {
                char substitutionChar = permutatedAlphabet.charAt(index);
                sb.append(Character.isUpperCase(c) ? Character.toUpperCase(substitutionChar)
                        : Character.toLowerCase(substitutionChar));
            }
        }
        return sb.toString();
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null)
            return null;

        StringBuilder sb = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            int index = permutatedAlphabet.toLowerCase().indexOf(Character.toLowerCase(c));
            if (index == -1) {
                sb.append(c);
            } else {
                sb.append(AlphabetUtils.indexToChar(index, Character.isUpperCase(c)));
            }
        }
        return sb.toString();
    }
}
