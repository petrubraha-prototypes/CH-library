package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

/** dCTR has no NIST vector; it is checked against CTR with the equivalent fixed counter. */
class DctrModeTest {

    private static final byte[] MESSAGE = Bytes.fromHex("00112233445566778899aabbcc");
    private final BlockCipher blockCipher = new ToyBlockCipher();

    @Test
    void roundTrip() {
        Cipher dctr = new DctrMode(blockCipher);
        assertArrayEquals(MESSAGE, dctr.decrypt(dctr.encrypt(MESSAGE)));
    }

    @Test
    void defaultMatchesCtrStartingAtOne() {
        Cipher ctr = new CtrMode(blockCipher, Bytes.fromHex("00000001"));
        assertArrayEquals(ctr.encrypt(MESSAGE), new DctrMode(blockCipher).encrypt(MESSAGE));
    }

    @Test
    void explicitCounterMatchesCtrWithThatCounter() {
        Cipher ctr = new CtrMode(blockCipher, Bytes.fromHex("00000105"));
        assertArrayEquals(ctr.encrypt(MESSAGE), new DctrMode(blockCipher, 0x105).encrypt(MESSAGE));
    }

    @Test
    void sameMessageAlwaysGivesTheSameCiphertext() {
        byte[] first = new DctrMode(blockCipher).encrypt(MESSAGE);
        byte[] second = new DctrMode(blockCipher).encrypt(MESSAGE);
        assertArrayEquals(first, second);
    }

    @ParameterizedTest
    @CsvSource({
            "0, 4, 00000000",
            "1, 4, 00000001",
            "4294967295, 4, ffffffff",
            "1, 16, 00000000000000000000000000000001",
            "9223372036854775807, 16, 00000000000000007fffffffffffffff",
    })
    void counterBlockIsBigEndian(long counter, int blockSize, String expectedHex) {
        assertArrayEquals(Bytes.fromHex(expectedHex), DctrMode.counterBlock(counter, blockSize));
    }

    @Test
    void rejectsNegativeCounter() {
        assertThrows(IllegalArgumentException.class, () -> new DctrMode(blockCipher, -1));
    }

    @Test
    void rejectsCounterThatDoesNotFitInTheBlock() {
        assertThrows(IllegalArgumentException.class, () -> new DctrMode(blockCipher, 0x100000000L));
    }
}
