package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class CtrModeTest {

    private static final byte[] INITIAL_COUNTER = Bytes.fromHex("000000fe");
    private final BlockCipher blockCipher = new ToyBlockCipher();

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 4, 6, 13 })
    void roundTripWithoutPadding(int length) {
        Cipher ctr = new CtrMode(blockCipher, INITIAL_COUNTER);
        byte[] plaintext = new byte[length];
        assertArrayEquals(plaintext, ctr.decrypt(ctr.encrypt(plaintext)));
    }

    @Test
    void ciphertextHasThePlaintextLength() {
        Cipher ctr = new CtrMode(blockCipher, INITIAL_COUNTER);
        assertEquals(7, ctr.encrypt(new byte[7]).length);
    }

    @Test
    void xorsTheDataWithEncryptedSuccessiveCounters() {
        Cipher ctr = new CtrMode(blockCipher, INITIAL_COUNTER);
        byte[] plaintext = Bytes.fromHex("00112233 445566");
        byte[] firstKeystream = blockCipher.encryptBlock(Bytes.fromHex("000000fe"));
        byte[] secondKeystream = blockCipher.encryptBlock(Bytes.fromHex("000000ff"));
        byte[] expected = Blocks.join(List.of(
                Bytes.xor(Bytes.fromHex("00112233"), firstKeystream),
                Blocks.xorWithLeadingBytes(Bytes.fromHex("445566"), secondKeystream)));
        assertArrayEquals(expected, ctr.encrypt(plaintext));
    }

    @ParameterizedTest
    @CsvSource({
            "00000000, 00000001",
            "000000ff, 00000100",
            "00ffffff, 01000000",
            "ffffffff, 00000000",
    })
    void incrementAddsOneBigEndianWithWraparound(String counterHex, String expectedHex) {
        assertArrayEquals(Bytes.fromHex(expectedHex), CtrMode.increment(Bytes.fromHex(counterHex)));
    }

    @Test
    void incrementDoesNotModifyItsInput() {
        byte[] counter = Bytes.fromHex("00000001");
        CtrMode.increment(counter);
        assertArrayEquals(Bytes.fromHex("00000001"), counter);
    }

    @Test
    void rejectsCounterOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new CtrMode(blockCipher, new byte[5]));
    }
}
