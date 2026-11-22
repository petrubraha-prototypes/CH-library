package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class OfbModeTest {

    private static final byte[] IV = Bytes.fromHex("0f1e2d3c");
    private final BlockCipher blockCipher = new ToyBlockCipher();

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 4, 9 })
    void roundTripWithoutPadding(int length) {
        Cipher ofb = new OfbMode(blockCipher, IV);
        byte[] plaintext = new byte[length];
        assertArrayEquals(plaintext, ofb.decrypt(ofb.encrypt(plaintext)));
    }

    @Test
    void keystreamIsTheRepeatedlyEncryptedIv() {
        Cipher ofb = new OfbMode(blockCipher, IV);
        byte[] firstOutput = blockCipher.encryptBlock(IV);
        byte[] secondOutput = blockCipher.encryptBlock(firstOutput);
        byte[] expected = Blocks.join(List.of(firstOutput, Blocks.xorWithLeadingBytes(new byte[2], secondOutput)));
        assertArrayEquals(expected, ofb.encrypt(new byte[6]));
    }

    @Test
    void keystreamDoesNotDependOnTheData() {
        Cipher ofb = new OfbMode(blockCipher, IV);
        byte[] first = Bytes.fromHex("0011223344556677");
        byte[] second = Bytes.fromHex("8899aabbccddeeff");
        byte[] ciphertextDifference = Bytes.xor(ofb.encrypt(first), ofb.encrypt(second));
        assertArrayEquals(Bytes.xor(first, second), ciphertextDifference);
    }

    @Test
    void rejectsIvOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new OfbMode(blockCipher, new byte[8]));
    }

    /** NIST SP 800-38A, F.4.1 and F.4.2: OFB-AES128. */
    @Test
    void matchesNistSp80038aWithAes128() {
        Cipher cipher = new OfbMode(Sp80038aVectors.aes128(), Sp80038aVectors.INITIALIZATION_VECTOR);
        byte[] ciphertext = Bytes.fromHex("3b3fd92eb72dad20333449f8e83cfb4a"
                + "7789508d16918f03f53c52dac54ed825"
                + "9740051e9c5fecf64344f7a82260edcc"
                + "304c6528f659c77866a510d9c1d6ae5e");
        assertArrayEquals(ciphertext, cipher.encrypt(Sp80038aVectors.PLAINTEXT));
        assertArrayEquals(Sp80038aVectors.PLAINTEXT, cipher.decrypt(ciphertext));
    }
}
