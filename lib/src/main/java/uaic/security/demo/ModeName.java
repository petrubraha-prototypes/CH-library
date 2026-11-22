package uaic.security.demo;

import java.util.EnumSet;
import java.util.Set;

import lombok.RequiredArgsConstructor;

/**
 * The modes of operation a demo user can wrap a block cipher in.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@RequiredArgsConstructor
enum ModeName implements Choice {
    ECB("ecb"),
    CBC("cbc"),
    CTR("ctr"),
    DCTR("dctr"),
    OFB("ofb"),
    CFB("cfb");

    /** ECB has no IV; dCTR always starts from the fixed counter 1. */
    private static final Set<ModeName> WITHOUT_IV = EnumSet.of(ECB, DCTR);

    private final String label;

    @Override
    public String label() {
        return label;
    }

    /**
     * @return whether the mode is configured with an IV or initial counter block
     */
    boolean requiresIv() {
        return !WITHOUT_IV.contains(this);
    }
}
