package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class ChoiceTest {

    @Test
    void findMatchesTheLabelIgnoringCaseAndSpaces() {
        assertEquals(Optional.of(CipherName.TRIPLE_DES), Choice.find(CipherName.values(), " 3DES "));
    }

    @Test
    void findReturnsEmptyForUnknownLabels() {
        assertEquals(Optional.empty(), Choice.find(ModeName.values(), "xts"));
    }

    @Test
    void describeListsEveryLabel() {
        assertEquals("encrypt, decrypt", Choice.describe(Operation.values()));
    }
}
