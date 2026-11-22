package uaic.security;

import uaic.security.classic.AffineCipher;
import uaic.security.classic.CharCipher;
import uaic.security.classic.PermutationCipher;
import uaic.security.classic.SubstitutionCipher;
import uaic.security.classic.TranspositionCipher;
import uaic.security.classic.VigenereCipher;

public class Library {
    public static void main(String[] args) {
        String message = (args.length > 0) ? args[0] : "IloveMyGirlfriend2026";
        System.out.println("Original Message: " + message);
        System.out.println("----------------------------------------");

        // 1. Substitution Cipher
        String substitutionAlphabet = "qwertyuiopasdfghjklzxcvbnm";
        CharCipher substitution = new SubstitutionCipher(substitutionAlphabet);
        demonstrate(substitution, "Substitution Cipher", message);

        // 2. Permutation Cipher (Block Transposition)
        // A permutation of [0, 1, 2, 3]
        int[] permutationKey = { 2, 3, 0, 1 };
        CharCipher permutation = new PermutationCipher(permutationKey);
        demonstrate(permutation, "Permutation Cipher (Block Transposition)", message);

        // 3. Transposition Cipher (Columnar)
        CharCipher transposition = new TranspositionCipher("SECRET");
        demonstrate(transposition, "Transposition Cipher (Columnar)", message);

        // 4. Affine Cipher (a must be coprime to 26; e.g., 5 and 8)
        CharCipher affine = new AffineCipher(5, 8);
        demonstrate(affine, "Affine Cipher", message);

        // 5. Vigenere Cipher
        CharCipher vigenere = new VigenereCipher("KEYWORD");
        demonstrate(vigenere, "Vigenere Cipher", message);
    }

    private static void demonstrate(CharCipher cipher, String name, String message) {
        System.out.println("Demo: " + name);
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        System.out.println("  Encrypted: " + encrypted);
        System.out.println("  Decrypted: " + decrypted);
        System.out.println("  Match: " + message.equals(decrypted));
        System.out.println("----------------------------------------");
    }
}
