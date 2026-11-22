package uaic.security.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import uaic.security.Cipher;
import uaic.security.util.Bytes;

/**
 * Intermediate values come from the examples in Bernstein's "Salsa20
 * specification" (https://cr.yp.to/snuffle/spec.pdf); full keystream vectors
 * come from the ECRYPT eSTREAM file
 * {@code submissions/salsa20/full/verified.test-vectors}.
 */
class Salsa20KeystreamTest {

    private static final int[] FIRST_QUARTER = { 0, 1, 2, 3 };
    private static final byte[] ZERO_NONCE = new byte[8];

    private static int[] words(String hexWords) {
        String[] parts = hexWords.trim().split("\\s+");
        int[] result = new int[parts.length];
        for (int index = 0; index < parts.length; index++) {
            result[index] = Integer.parseUnsignedInt(parts[index], 16);
        }
        return result;
    }

    private static byte[] keystreamAt(Keystream keystream, int offset, int length) {
        keystream.fill(new byte[offset]);
        byte[] output = new byte[length];
        keystream.fill(output);
        return output;
    }

    /** Section 3 examples. */
    @ParameterizedTest
    @CsvSource({
            "00000000 00000000 00000000 00000000, 00000000 00000000 00000000 00000000",
            "00000001 00000000 00000000 00000000, 08008145 00000080 00010200 20500000",
            "00000000 00000001 00000000 00000000, 88000100 00000001 00000200 00402000",
            "00000000 00000000 00000001 00000000, 80040000 00000000 00000001 00002000",
            "00000000 00000000 00000000 00000001, 00048044 00000080 00010000 20100001",
            "e7e8c006 c4f9417d 6479b4b2 68c67137, e876d72b 9361dfd5 f1460244 948541a3",
            "d3917c5b 55f1c407 52a58a7a 8f887a3b, 3e2f308c d90a8f36 6ab2a923 2883524c",
    })
    void quarterRoundMatchesTheSpecification(String input, String expected) {
        int[] state = words(input);
        Salsa20Keystream.quarterRound(state, FIRST_QUARTER);
        assertArrayEquals(words(expected), state);
    }

    /** Section 4, second example. */
    @Test
    void rowRoundMatchesTheSpecification() {
        int[] state = words("08521bd6 1fe88837 bb2aa576 3aa26365 c54c6a5b 2fc74c2f 6dd39cc3 da0a64f6"
                + " 90a2f23d 067f95a6 06b35f61 41e4732e e859c100 ea4d84b7 0f619bff bc6e965a");
        Salsa20Keystream.rowRound(state);
        assertArrayEquals(words("a890d39d 65d71596 e9487daa c8ca6a86 949d2192 764b7754 e408d9b9 7a41b4d1"
                + " 3402e183 3c3af432 50669f96 d89ef0a8 0040ede5 b545fbce d257ed4f 1818882d"), state);
    }

    /** Section 5, second example. */
    @Test
    void columnRoundMatchesTheSpecification() {
        int[] state = words("08521bd6 1fe88837 bb2aa576 3aa26365 c54c6a5b 2fc74c2f 6dd39cc3 da0a64f6"
                + " 90a2f23d 067f95a6 06b35f61 41e4732e e859c100 ea4d84b7 0f619bff bc6e965a");
        Salsa20Keystream.columnRound(state);
        assertArrayEquals(words("8c9d190a ce8e4c90 1ef8e9d3 1326a71a 90a20123 ead3c4f3 63a091a0 f0708d69"
                + " 789b010c d195a681 eb7d5504 a774135c 481c2027 53a8e4b5 4c1f89c5 3f78c9c8"), state);
    }

    /** Section 6, second example. */
    @Test
    void doubleRoundMatchesTheSpecification() {
        int[] state = words("de501066 6f9eb8f7 e4fbbd9b 454e3f57 b75540d3 43e93a4c 3a6f2aa0 726d6b36"
                + " 9243f484 9145d1e8 4fa9d247 dc8dee11 054bf545 254dd653 d9421b6d 67b276c1");
        Salsa20Keystream.doubleRound(state);
        assertArrayEquals(words("ccaaf672 23d960f7 9153e63a cd9a60d0 50440492 f07cad19 ae344aa0 df4cfdfc"
                + " ca531c29 8e7943db ac1680cd d503ca00 a74b2ad6 bc331c5c 1dda24c7 ee928277"), state);
    }

    /** Section 8, the zero example and the second example (decimal bytes converted to hex). */
    @ParameterizedTest
    @CsvSource({
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,"
                    + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "d39f0d734c3752b70375de25bfbbea8831edb330016ab2dbafc7a6305610b3cf1ff0203f0f535da174933071ee37cc244fc9eb4f03519c2fcb1af4f358766836,"
                    + "6d2ab2a89cf0f8eea8c4becb1a6eaa9a1d1d961a961eebf9bea3fb30459033397628989db4391b5e6b2aec231b6f7272dbece8876f9b6e1218e85f9eb31330ca",
    })
    void hashMatchesTheSpecification(String inputHex, String expectedHex) {
        assertArrayEquals(Bytes.fromHex(expectedHex), Salsa20Keystream.hash(Bytes.fromHex(inputHex)));
    }

    /** Section 9 examples: k0 = 1..16, k1 = 201..216, n = 101..116. */
    @ParameterizedTest
    @CsvSource({
            "0102030405060708090a0b0c0d0e0f10c9cacbcccdcecfd0d1d2d3d4d5d6d7d8,"
                    + "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a",
            "0102030405060708090a0b0c0d0e0f10,"
                    + "27ad2ef81ec852113043feef25120df7f1c83d900a3732b9062ff6fd8f56bbe186556ef6a1a32bebe75eab3391d6701d0ee80510978cb78dab097ab568b6b1c1",
    })
    void expansionMatchesTheSpecification(String keyHex, String expectedHex) {
        byte[] input = Bytes.fromHex("65666768696a6b6c6d6e6f7071727374");
        assertArrayEquals(Bytes.fromHex(expectedHex), Salsa20Keystream.expand(Bytes.fromHex(keyHex), input));
    }

    /** ECRYPT verified test vectors: stream[offset .. offset + 63]. */
    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "128-bit set 1 vector 0, 80000000000000000000000000000000, 0000000000000000, 0,"
                    + "4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F"
                    + "2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA",
            "128-bit set 1 vector 0, 80000000000000000000000000000000, 0000000000000000, 192,"
                    + "DA9C1581F429E0A00F7D67E23B730676783B262E8EB43A25F55FB90B3E753AEF"
                    + "8C6713EC66C51881111593CCB3E8CB8F8DE124080501EEEB389C4BCB6977CF95",
            "256-bit set 1 vector 0, 8000000000000000000000000000000000000000000000000000000000000000, 0000000000000000, 0,"
                    + "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844"
                    + "B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117",
            "256-bit set 1 vector 0, 8000000000000000000000000000000000000000000000000000000000000000, 0000000000000000, 192,"
                    + "57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9"
                    + "ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17",
            "256-bit set 6 vector 0, 0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D, 0D74DB42A91077DE, 0,"
                    + "F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EA"
                    + "F24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71",
            "256-bit set 6 vector 0, 0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D, 0D74DB42A91077DE, 65536,"
                    + "81582C65D7562B80AEC2F1A673A9D01C9F892A23D4919F6AB47B9154E08E699B"
                    + "4117D7C666477B60F8391481682F5D95D96623DBC489D88DAA6956B9F0646B6E",
    })
    void keystreamMatchesEcryptVectors(String name, String keyHex, String nonceHex, int offset, String expectedHex) {
        Keystream keystream = new Salsa20Keystream(Bytes.fromHex(keyHex), Bytes.fromHex(nonceHex));
        byte[] expected = Bytes.fromHex(expectedHex);
        assertArrayEquals(expected, keystreamAt(keystream, offset, expected.length));
    }

    @Test
    void roundTripThroughStreamCipher() {
        byte[] key = Bytes.fromHex("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D");
        byte[] nonce = Bytes.fromHex("0D74DB42A91077DE");
        Cipher cipher = new StreamCipher(() -> new Salsa20Keystream(key, nonce));
        byte[] message = new byte[150];
        for (int index = 0; index < message.length; index++) {
            message[index] = (byte) index;
        }
        assertArrayEquals(message, cipher.decrypt(cipher.encrypt(message)));
    }

    @Test
    void rejectsUnsupportedKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new Salsa20Keystream(new byte[24], ZERO_NONCE));
    }

    @Test
    void rejectsUnsupportedNonceLength() {
        assertThrows(IllegalArgumentException.class, () -> new Salsa20Keystream(new byte[32], new byte[12]));
    }
}
