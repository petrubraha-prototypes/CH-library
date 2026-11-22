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
}
