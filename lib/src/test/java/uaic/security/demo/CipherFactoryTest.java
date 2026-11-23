package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import uaic.security.Cipher;
import uaic.security.util.Bytes;

class CipherFactoryTest {

    private static final String AES_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
    private static final String AES_IV = "000102030405060708090a0b0c0d0e0f";
    private static final String NIST_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

    private static Cipher create(CipherName cipher, String key, String nonceOrIv, ModeName mode) {
        return CipherFactory.create(new CipherRequest(cipher, Operation.ENCRYPT, key, nonceOrIv, mode, ""));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "AFFINE | 5,8 | | | AttackAtDawn",
            "SUBSTITUTION | qwertyuiopasdfghjklzxcvbnm | | | AttackAtDawn",
            "PERMUTATION | 2,3,0,1 | | | AttackAtDawn",
            "TRANSPOSITION | SECRET | | | AttackAtDawn",
            "VIGENERE | KEYWORD | | | AttackAtDawn",
            "RC4 | 0102030405 | | | 00112233445566778899",
            "SALSA20 | 000102030405060708090a0b0c0d0e0f | 0001020304050607 | | 00112233445566778899",
            "CHACHA20 | 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f | 000000000000004a00000000 | | 0011",
            "DES | 133457799BBCDFF1 | | ECB | 00112233445566778899",
            "TRIPLE_DES | 0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123 | 1234567890ABCDEF | CBC | 0011223344",
            "AES128 | 2b7e151628aed2a6abf7158809cf4f3c | 000102030405060708090a0b0c0d0e0f | CTR | 0011223344",
            "AES128 | 2b7e151628aed2a6abf7158809cf4f3c | | DCTR | 0011223344",
            "AES128 | 2b7e151628aed2a6abf7158809cf4f3c | 000102030405060708090a0b0c0d0e0f | OFB | 0011223344",
            "AES128 | 2b7e151628aed2a6abf7158809cf4f3c | 000102030405060708090a0b0c0d0e0f | CFB | 0011223344",
    })
    void everyConfigurationRoundTrips(CipherName cipher, String key, String nonceOrIv, ModeName mode, String input) {
        Cipher configured = create(cipher, key, nonceOrIv, mode);
        byte[] data = cipher.family().dataFormat().parse(input);
        assertArrayEquals(data, configured.decrypt(configured.encrypt(data)));
    }

    /** NIST SP 800-38A F.2.1; PKCS#7 then appends one more block. */
    @Test
    void aesCbcStartsWithTheNistCiphertext() {
        Cipher cipher = create(CipherName.AES128, AES_KEY, AES_IV, ModeName.CBC);
        byte[] ciphertext = cipher.encrypt(Bytes.fromHex(NIST_PLAINTEXT));
        byte[] expected = Bytes.fromHex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
        assertArrayEquals(expected, Arrays.copyOf(ciphertext, expected.length));
    }

    /** RFC 8439 section 2.4.2 uses block counter 1, as the factory does. */
    @Test
    void chaCha20MatchesRfc8439() {
        Cipher cipher = create(CipherName.CHACHA20,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000000000004a00000000", null);
        byte[] plaintext = "Ladies and Gentlemen".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(Bytes.fromHex("6e2e359a2568f98041ba0728dd0d6981e97e7aec"), cipher.encrypt(plaintext));
    }

    /** NIST CAVP TECBMMT3 COUNT 0, with the three keys given as one K1 | K2 | K3 bundle. */
    @Test
    void tripleDesSplitsTheKeyBundle() {
        Cipher cipher = create(CipherName.TRIPLE_DES, "e97c8313ba265d43254cbf9e8f7c2aa8a754d65e8ae997e3", null,
                ModeName.ECB);
        byte[] ciphertext = cipher.encrypt(Bytes.fromHex("4656ed81a8bc58a9"));
        assertArrayEquals(Bytes.fromHex("426a0ac26586bf6c"), Arrays.copyOf(ciphertext, 8));
    }

    @Test
    void dctrStartsAtCounterOne() {
        Cipher dctr = create(CipherName.AES128, AES_KEY, null, ModeName.DCTR);
        Cipher ctr = create(CipherName.AES128, AES_KEY, "00000000000000000000000000000001", ModeName.CTR);
        byte[] plaintext = Bytes.fromHex(NIST_PLAINTEXT);
        assertArrayEquals(ctr.encrypt(plaintext), dctr.encrypt(plaintext));
    }

    @Test
    void rejectsAffineKeyWithoutTwoNumbers() {
        assertThrows(IllegalArgumentException.class, () -> create(CipherName.AFFINE, "5", null, null));
    }

    @Test
    void rejectsNonNumericPermutationKey() {
        assertThrows(IllegalArgumentException.class, () -> create(CipherName.PERMUTATION, "a,b", null, null));
    }

    @Test
    void rejectsTripleDesBundleOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class,
                () -> create(CipherName.TRIPLE_DES, "0123456789ABCDEF", null, ModeName.ECB));
    }

    @Test
    void rejectsIvOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> create(CipherName.AES128, AES_KEY, "00", ModeName.CBC));
    }
}
