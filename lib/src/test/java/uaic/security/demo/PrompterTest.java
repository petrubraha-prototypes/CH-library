package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class PrompterTest {

    private final ByteArrayOutputStream printed = new ByteArrayOutputStream();

    private Prompter prompterReading(String answers) {
        ByteArrayInputStream input = new ByteArrayInputStream(answers.getBytes(StandardCharsets.UTF_8));
        return new Prompter(input, new PrintStream(printed, true, StandardCharsets.UTF_8));
    }

    private String printedText() {
        return printed.toString(StandardCharsets.UTF_8);
    }

    @Test
    void returnsTheFirstValidAnswerTrimmed() {
        Prompter prompter = prompterReading("  yes  \n");
        assertEquals("yes", prompter.ask("answer", "yes"::equals, "yes"));
        assertTrue(printedText().startsWith("answer: "));
    }

    @Test
    void repeatsTheQuestionAfterAnInvalidAnswer() {
        Prompter prompter = prompterReading("maybe\nyes\n");
        assertEquals("yes", prompter.ask("answer", "yes"::equals, "yes"));
        assertTrue(printedText().contains("Invalid answer. Allowed: yes"));
    }

    @Test
    void failsWhenTheInputEnds() {
        Prompter prompter = prompterReading("maybe\n");
        assertThrows(UsageException.class, () -> prompter.ask("answer", "yes"::equals, "yes"));
    }
}
