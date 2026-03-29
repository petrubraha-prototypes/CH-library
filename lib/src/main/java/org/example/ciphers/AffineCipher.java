package org.example.ciphers;

import org.example.util.AlphabetUtils;

import lombok.RequiredArgsConstructor;

/**
 * Implementation of the Affine cipher.
 * E(x) = (ax + b) mod m
 * D(x) = a^-1 (x - b) mod m
 */
@RequiredArgsConstructor
public class AffineCipher implements Cipher {
    private final int a;
    private final int b;

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null)
            return null;

        StringBuilder sb = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            int x = AlphabetUtils.charToIndex(c);
            if (x == -1) {
                sb.append(c);
            } else {
                int encrypted = (a * x + b) % AlphabetUtils.ALPHABET_SIZE;
                sb.append(AlphabetUtils.indexToChar(encrypted, Character.isUpperCase(c)));
            }
        }
        return sb.toString();
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null)
            return null;

        int aInverse = AlphabetUtils.modInverse(a, AlphabetUtils.ALPHABET_SIZE);
        StringBuilder sb = new StringBuilder();
        for (char c : ciphertext.toCharArray()) {
            int x = AlphabetUtils.charToIndex(c);
            if (x == -1) {
                sb.append(c);
            } else {
                int decrypted = (aInverse * (x - b)) % AlphabetUtils.ALPHABET_SIZE;
                if (decrypted < 0)
                    decrypted += AlphabetUtils.ALPHABET_SIZE;
                sb.append(AlphabetUtils.indexToChar(decrypted, Character.isUpperCase(c)));
            }
        }
        return sb.toString();
    }
}
