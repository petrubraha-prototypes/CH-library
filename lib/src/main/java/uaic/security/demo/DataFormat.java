package uaic.security.demo;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import lombok.RequiredArgsConstructor;
import uaic.security.util.Bytes;

/**
 * How the demo reads and prints data: hex for the byte ciphers, plain UTF-8
 * text for the classical ciphers.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@RequiredArgsConstructor
enum DataFormat {
    HEX("hex", Bytes::fromHex, Bytes::toHex),
    TEXT("plain text", text -> text.getBytes(StandardCharsets.UTF_8),
            bytes -> new String(bytes, StandardCharsets.UTF_8));

    private final String description;
    private final Function<String, byte[]> parser;
    private final Function<byte[], String> formatter;

    /**
     * @return a short name for prompts, such as "hex"
     */
    String description() {
        return description;
    }

    /**
     * Converts what the user typed into bytes.
     *
     * @throws IllegalArgumentException if the text is not valid in this format
     */
    byte[] parse(String text) {
        return parser.apply(text);
    }

    /** Converts a result into printable text. */
    String format(byte[] bytes) {
        return formatter.apply(bytes);
    }

    /** Checks whether the text can be parsed in this format. */
    boolean accepts(String text) {
        try {
            parse(text);
            return true;
        } catch (IllegalArgumentException invalidText) {
            return false;
        }
    }
}
