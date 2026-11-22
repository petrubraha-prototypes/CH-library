package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class CryptoDemoTest {

    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errors = new ByteArrayOutputStream();

    private int run(String answers, String... arguments) {
        ByteArrayInputStream input = new ByteArrayInputStream(answers.getBytes(StandardCharsets.UTF_8));
        return CryptoDemo.run(arguments, input, new PrintStream(output, true, StandardCharsets.UTF_8),
                new PrintStream(errors, true, StandardCharsets.UTF_8));
    }

    private String printed() {
        return output.toString(StandardCharsets.UTF_8).strip();
    }

    private String errorText() {
        return errors.toString(StandardCharsets.UTF_8);
    }

    /** NIST SP 800-38A F.5.1, first block. */
    @Test
    void printsTheHexResultOfAByteCipher() {
        int status = run("", "aes128", "encrypt", "2b7e151628aed2a6abf7158809cf4f3c",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "ctr", "6bc1bee22e409f96e93d7e117393172a");
        assertEquals(CryptoDemo.SUCCESS, status);
        assertEquals("874d6191b620e3261bef6864990db6ce", printed());
    }

    /** RFC 6229: the first RC4 keystream bytes for key 0102030405, exposed by encrypting zeros. */
    @Test
    void decryptsWithAStreamCipher() {
        int status = run("", "rc4", "decrypt", "0102030405", "b2396305");
        assertEquals(CryptoDemo.SUCCESS, status);
        assertEquals("00000000", printed());
    }

    @Test
    void printsTheTextResultOfAClassicalCipher() {
        int status = run("", "vigenere", "decrypt", "KEY", "Kxrkgi kx bkal");
        assertEquals(CryptoDemo.SUCCESS, status);
        assertEquals("Attack at dawn", printed());
    }

    @Test
    void promptsForMissingFields() {
        int status = run("encrypt\nKEY\nAttack at dawn\n", "vigenere");
        assertEquals(CryptoDemo.SUCCESS, status);
        assertTrue(printed().endsWith("Kxrkgi kx bkal"));
    }

    @Test
    void invalidArgumentPrintsTheUsage() {
        int status = run("", "aes256", "encrypt");
        assertEquals(CryptoDemo.USAGE_ERROR, status);
        assertTrue(errorText().contains("Allowed: affine, substitution"));
        assertTrue(errorText().contains("Usage: <cipher> <op> <key> [iv/nonce] [mode] <input>"));
    }

    @Test
    void rejectedKeyPrintsTheReason() {
        int status = run("", "aes128", "encrypt", "00", "ecb", "00");
        assertEquals(CryptoDemo.INVALID_VALUE, status);
        assertTrue(errorText().contains("AES-128 key must be 16 bytes"));
    }
}
