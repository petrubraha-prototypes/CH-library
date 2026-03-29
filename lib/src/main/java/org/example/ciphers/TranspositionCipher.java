package org.example.ciphers;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Columnar Transposition Cipher.
 * Rearranges message in columns based on an alphabetical key.
 */
@RequiredArgsConstructor
public class TranspositionCipher implements Cipher {
    @NonNull
    private final String key;

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null)
            return null;

        int numCols = key.length();
        int numRows = (int) Math.ceil((double) plaintext.length() / numCols);
        char[][] grid = new char[numRows][numCols];

        // Fill row by row with special character if incomplete
        for (int i = 0, k = 0; i < numRows; i++) {
            for (int j = 0; j < numCols; j++) {
                grid[i][j] = (k < plaintext.length()) ? plaintext.charAt(k++) : '\0';
            }
        }

        // Sort columns alphabetically by key
        Integer[] order = new Integer[numCols];
        for (int i = 0; i < numCols; i++)
            order[i] = i;
        Arrays.sort(order, Comparator.comparingInt(i -> key.charAt(i)));

        StringBuilder sb = new StringBuilder();
        for (int col : order) {
            for (int row = 0; row < numRows; row++) {
                if (grid[row][col] != '\0') {
                    sb.append(grid[row][col]);
                }
            }
        }
        return sb.toString();
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null)
            return null;

        int numCols = key.length();
        int numRows = (int) Math.ceil((double) ciphertext.length() / numCols);
        char[][] grid = new char[numRows][numCols];

        // Decryption logic:
        // Calculate the number of full cells in each column
        int fullCells = ciphertext.length();
        int extraCells = fullCells % numCols;
        int[] colHeights = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            colHeights[i] = (fullCells / numCols) + (i < extraCells ? 1 : 0);
        }

        // Get sorted order
        Integer[] order = new Integer[numCols];
        for (int i = 0; i < numCols; i++)
            order[i] = i;
        Arrays.sort(order, Comparator.comparingInt(i -> key.charAt(i)));

        // Read ciphertext into the columns based on their height in the original order
        int k = 0;
        for (int colIndex : order) {
            for (int rowIndex = 0; rowIndex < colHeights[colIndex]; rowIndex++) {
                grid[rowIndex][colIndex] = ciphertext.charAt(k++);
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numRows; i++) {
            for (int j = 0; j < numCols; j++) {
                if (grid[i][j] != '\0') {
                    sb.append(grid[i][j]);
                }
            }
        }
        return sb.toString();
    }
}
