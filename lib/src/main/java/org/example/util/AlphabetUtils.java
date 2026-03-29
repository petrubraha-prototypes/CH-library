package org.example.util;

import lombok.experimental.UtilityClass;

/**
 * Common alphabet constants and utility methods for ciphers.
 */
@UtilityClass
public class AlphabetUtils {
    public static final String ENGLISH_LOWER = "abcdefghijklmnopqrstuvwxyz";
    public static final int ALPHABET_SIZE = 26;

    /**
     * Finds the modular multiplicative inverse of a modulo m using the Extended
     * Euclidean Algorithm.
     * 
     * @param a the number to find the inverse for
     * @param m the modulus
     * @return the inverse of a modulo m
     * @throws IllegalArgumentException if a and m are not coprime
     */
    public static int modInverse(int a, int m) {
        a = ((a % m) + m) % m;
        for (int x = 1; x < m; x++) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        throw new IllegalArgumentException(
                "No modular multiplicative inverse exists for " + a + " and " + m + " (they are not coprime).");
    }

    /**
     * Normalizes a character to its 0-25 index in the English lower-case alphabet.
     * Non-alphabetic characters return -1.
     */
    public static int charToIndex(char c) {
        char lower = Character.toLowerCase(c);
        if (lower >= 'a' && lower <= 'z') {
            return lower - 'a';
        }
        return -1;
    }

    /**
     * Maps an index 0-25 to its character in the English alphabet.
     */
    public static char indexToChar(int index, boolean upper) {
        char c = (char) ('a' + (index % ALPHABET_SIZE + ALPHABET_SIZE) % ALPHABET_SIZE);
        return upper ? Character.toUpperCase(c) : c;
    }
}
