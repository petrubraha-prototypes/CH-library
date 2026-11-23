package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class DataFormatTest {

    @Test
    void hexParsesAndFormatsBytes() {
        byte[] bytes = DataFormat.HEX.parse("00ff10");
        assertArrayEquals(new byte[] { 0x00, (byte) 0xff, 0x10 }, bytes);
        assertEquals("00ff10", DataFormat.HEX.format(bytes));
    }

    @Test
    void textUsesUtf8() {
        byte[] bytes = DataFormat.TEXT.parse("Hi ă");
        assertArrayEquals("Hi ă".getBytes(StandardCharsets.UTF_8), bytes);
        assertEquals("Hi ă", DataFormat.TEXT.format(bytes));
    }

    @Test
    void hexAcceptsOnlyValidHex() {
        assertTrue(DataFormat.HEX.accepts("0a0b"));
        assertFalse(DataFormat.HEX.accepts("xyz"));
    }

    @Test
    void textAcceptsAnything() {
        assertTrue(DataFormat.TEXT.accepts("any text, 123!"));
    }
}
