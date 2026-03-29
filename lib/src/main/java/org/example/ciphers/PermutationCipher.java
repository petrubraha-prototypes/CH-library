package org.example.ciphers;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Permutation cipher (Block Transposition).
 * Rearranges characters within blocks of text according to a specified
 * permutation key.
 */
@RequiredArgsConstructor
public class PermutationCipher implements Cipher {
    @NonNull
    private final int[] permutationKey;

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null)
            return null;

        int blockSize = permutationKey.length;
        int paddedLength = (plaintext.length() + blockSize - 1) / blockSize * blockSize;
        // Padding with null character for block completion (if necessary)
        String paddedPlaintext = String.format("%-" + paddedLength + "s", plaintext).replace(' ', '\0');

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < paddedPlaintext.length(); i += blockSize) {
            char[] block = paddedPlaintext.substring(i, i + blockSize).toCharArray();
            char[] permutatedBlock = new char[blockSize];
            for (int j = 0; j < blockSize; j++) {
                permutatedBlock[permutationKey[j]] = block[j];
            }
            sb.append(new String(permutatedBlock));
        }

        return sb.toString().replace("\0", "");
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null)
            return null;

        int blockSize = permutationKey.length;
        // Invert the permutation key
        int[] inverseKey = new int[blockSize];
        for (int i = 0; i < blockSize; i++) {
            inverseKey[permutationKey[i]] = i;
        }

        // Ciphertext should already be a multiple of blockSize if it was padded during
        // encryption.
        // If not, we handle it as per block size.
        int paddedLength = (ciphertext.length() + blockSize - 1) / blockSize * blockSize;
        String paddedCiphertext = String.format("%-" + paddedLength + "s", ciphertext).replace(' ', '\0');

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < paddedCiphertext.length(); i += blockSize) {
            char[] block = paddedCiphertext.substring(i, i + blockSize).toCharArray();
            char[] originalBlock = new char[blockSize];
            for (int j = 0; j < blockSize; j++) {
                originalBlock[inverseKey[j]] = block[j];
            }
            sb.append(new String(originalBlock));
        }

        return sb.toString().replace("\0", "");
    }
}
