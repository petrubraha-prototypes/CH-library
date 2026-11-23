package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class ModeNameTest {

    @Test
    void labelsMatchTheCommandLineNames() {
        assertEquals("ecb, cbc, ctr, dctr, ofb, cfb", Choice.describe(ModeName.values()));
    }

    @ParameterizedTest
    @EnumSource(value = ModeName.class, names = { "ECB", "DCTR" })
    void ecbAndDctrTakeNoIv(ModeName mode) {
        assertFalse(mode.requiresIv());
    }

    @ParameterizedTest
    @EnumSource(value = ModeName.class, names = { "CBC", "CTR", "OFB", "CFB" })
    void otherModesTakeAnIv(ModeName mode) {
        assertTrue(mode.requiresIv());
    }
}
