package uaic.security.mode;

import uaic.security.Cipher;

/**
 * A mode of operation: turns a single-block {@code BlockCipher}, plus its IV
 * or counter, into a {@link Cipher} that handles whole messages.
 *
 * <p>
 * All looping over blocks, IV handling, feedback and chaining live in the
 * implementations of this interface, never in the block cipher.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public interface BlockMode extends Cipher {
}
