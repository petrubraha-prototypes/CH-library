package uaic.security.stream;

import java.util.function.Supplier;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import uaic.security.Cipher;

/**
 * Turns any {@link Keystream} into a {@link Cipher} by XORing the message
 * with the keystream through {@link XorCombiner}.
 *
 * <p>
 * The algorithm is chosen by composition, for example
 * {@code new StreamCipher(() -> new Rc4Keystream(key))}. Each call to
 * {@link #encrypt(byte[])} or {@link #decrypt(byte[])} asks the supplier for
 * a fresh keystream, so every message starts at the first keystream byte and
 * {@code decrypt(encrypt(x))} on the same instance returns {@code x}.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@RequiredArgsConstructor
public class StreamCipher implements Cipher {
    @NonNull
    private final Supplier<Keystream> keystreamFactory;

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return combineWithFreshKeystream(plaintext);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        return combineWithFreshKeystream(ciphertext);
    }

    private byte[] combineWithFreshKeystream(byte[] data) {
        Keystream keystream = keystreamFactory.get();
        return XorCombiner.combine(data, keystream);
    }
}
