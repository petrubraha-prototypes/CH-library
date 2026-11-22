package uaic.security.block.aes;

import java.util.Arrays;

import uaic.security.util.Bytes;

/**
 * KEYEXPANSION() for AES-128 (FIPS 197, section 5.2): expands the 4-word key
 * into the 44 words w[0..43]. The first four words are the key; each later
 * word is {@code w[i] = w[i-4] XOR temp}, where {@code temp = w[i-1]}, and
 * every fourth word first replaces temp by
 * {@code SUBWORD(ROTWORD(temp)) XOR Rcon[i/4]}.
 *
 * <p>
 * A word holds its first byte in the most significant position, so
 * {@code 0x2b7e1516} is the byte sequence 2b 7e 15 16.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
class AesKeySchedule {
    static final int ROUNDS = 10;
    static final int KEY_LENGTH = 16;

    private static final int KEY_WORDS = 4;
    private static final int WORDS_PER_ROUND_KEY = 4;
    private static final int TOTAL_WORDS = WORDS_PER_ROUND_KEY * (ROUNDS + 1);
    private static final int BYTE_MASK = 0xFF;
    private static final int FIRST_ROUND_CONSTANT = 0x01;
    private static final int HIGH_BYTE_SHIFT = 24;

    private final int[] words = new int[TOTAL_WORDS];

    /**
     * @param key 16 bytes
     * @throws IllegalArgumentException if the key is not 16 bytes
     */
    AesKeySchedule(byte[] key) {
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("AES-128 key must be " + KEY_LENGTH + " bytes, got " + key.length);
        }
        int[] keyWords = Bytes.toIntsBigEndian(key);
        System.arraycopy(keyWords, 0, words, 0, KEY_WORDS);
        for (int index = KEY_WORDS; index < TOTAL_WORDS; index++) {
            int temp = words[index - 1];
            if (index % KEY_WORDS == 0) {
                temp = subWord(rotWord(temp)) ^ roundConstant(index / KEY_WORDS);
            }
            words[index] = words[index - KEY_WORDS] ^ temp;
        }
    }


    /**
     * Returns the round key used by ADDROUNDKEY() in one round.
     *
     * @param round 0 to 10
     * @return w[4*round .. 4*round + 3] as 16 bytes
     */
    byte[] roundKey(int round) {
        int firstWord = round * WORDS_PER_ROUND_KEY;
        int[] roundWords = Arrays.copyOfRange(words, firstWord, firstWord + WORDS_PER_ROUND_KEY);
        return Bytes.fromIntsBigEndian(roundWords);
    }

    /** Eq. 5.10: [a0, a1, a2, a3] becomes [a1, a2, a3, a0]. */
    static int rotWord(int word) {
        return Integer.rotateLeft(word, Byte.SIZE);
    }

    /** Eq. 5.11: applies SBOX() to each of the four bytes. */
    static int subWord(int word) {
        int substituted = 0;
        for (int shift = HIGH_BYTE_SHIFT; shift >= 0; shift -= Byte.SIZE) {
            int wordByte = (word >>> shift) & BYTE_MASK;
            substituted |= AesSBox.substitute(wordByte) << shift;
        }
        return substituted;
    }

    /**
     * Table 5: Rcon[j] = [x^(j-1), 00, 00, 00], where x^(j-1) is obtained by
     * applying XTIMES() j - 1 times to {01}.
     */
    static int roundConstant(int roundNumber) {
        int power = FIRST_ROUND_CONSTANT;
        for (int step = 1; step < roundNumber; step++) {
            power = AesGaloisField.xtime(power);
        }
        return power << HIGH_BYTE_SHIFT;
    }
}
