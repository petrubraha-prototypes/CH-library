package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class RequestReaderTest {

    private static final String KEY = "2b7e151628aed2a6abf7158809cf4f3c";
    private static final String IV = "000102030405060708090a0b0c0d0e0f";

    private static CipherRequest read(String answers, String... arguments) {
        ByteArrayInputStream input = new ByteArrayInputStream(answers.getBytes(StandardCharsets.UTF_8));
        PrintStream silent = new PrintStream(OutputStream.nullOutputStream());
        return new RequestReader(arguments, new Prompter(input, silent)).read();
    }

    @Test
    void readsABlockCipherWithIvFromArguments() {
        CipherRequest request = read("", "aes128", "encrypt", KEY, IV, "cbc", "00112233");
        assertEquals(new CipherRequest(CipherName.AES128, Operation.ENCRYPT, KEY, IV, ModeName.CBC, "00112233"),
                request);
    }

    @Test
    void readsABlockModeWithoutIvFromArguments() {
        CipherRequest request = read("", "aes128", "decrypt", KEY, "ecb", "00112233");
        assertEquals(new CipherRequest(CipherName.AES128, Operation.DECRYPT, KEY, null, ModeName.ECB, "00112233"),
                request);
    }

    @Test
    void readsAStreamCipherNonceFromArguments() {
        CipherRequest request = read("", "salsa20", "encrypt", KEY, "0001020304050607", "abcd");
        assertEquals("0001020304050607", request.nonceOrIv());
        assertEquals(null, request.mode());
    }

    @Test
    void readsAClassicalCipherWithTextFromArguments() {
        CipherRequest request = read("", "vigenere", "encrypt", "KEY", "Attack at dawn");
        assertEquals(new CipherRequest(CipherName.VIGENERE, Operation.ENCRYPT, "KEY", null, null, "Attack at dawn"),
                request);
    }

    @Test
    void promptsForEveryFieldWithoutArguments() {
        CipherRequest request = read("aes128\nencrypt\n" + KEY + "\nctr\n" + IV + "\n00ff\n");
        assertEquals(new CipherRequest(CipherName.AES128, Operation.ENCRYPT, KEY, IV, ModeName.CTR, "00ff"), request);
    }

    @Test
    void promptsOnlyForTheFieldsTheArgumentsMiss() {
        CipherRequest request = read("dctr\n00ff\n", "aes128", "encrypt", KEY);
        assertEquals(new CipherRequest(CipherName.AES128, Operation.ENCRYPT, KEY, null, ModeName.DCTR, "00ff"),
                request);
    }

    @Test
    void repromptsAfterAnInvalidInteractiveChoice() {
        CipherRequest request = read("aes256\naes128\nencrypt\n" + KEY + "\necb\n00\n");
        assertEquals(CipherName.AES128, request.cipher());
    }

    @Test
    void rejectsAnInvalidArgument() {
        assertThrows(UsageException.class, () -> read("", "aes256", "encrypt", KEY, "ecb", "00"));
    }

    @Test
    void rejectsNonHexKeyArgumentForByteCiphers() {
        assertThrows(UsageException.class, () -> read("", "rc4", "encrypt", "not-hex", "00"));
    }

    @Test
    void rejectsAnIvForAModeThatTakesNone() {
        assertThrows(UsageException.class, () -> read("", "aes128", "encrypt", KEY, IV, "ecb", "00"));
    }

    @Test
    void rejectsExtraArguments() {
        assertThrows(UsageException.class, () -> read("", "rc4", "encrypt", "0102030405", "00", "extra"));
    }
}
