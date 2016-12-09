package org.jasypt.salt;


import org.jasypt.exceptions.EncryptionInitializationException;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * <p>
 * This implementation of {@link IVGenerator} holds a <b>secure</b> random
 * generator which can be used for generating random IVs for encryption
 * or digesting.
 * </p>
 * <p>
 * The algorithm used for random number generation can be configured at
 * instantiation time. If not, the default algorithm will be used.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 *
 * @since 1.9.3
 *
 * @author Alex Scal
 *
 */
public class RandomIVGenerator implements IVGenerator {

    /**
     * The default algorithm to be used for secure random number
     * generation: set to SHA1PRNG.
     */
    private static final String GENERATOR_ALGORITHM = "SHA1PRNG";

    private final SecureRandom random;

    /**
     * Creates a new instance of <tt>RandomIVGenerator</tt> using the
     * default secure random number generation algorithm.
     */
    public RandomIVGenerator() {
        this(GENERATOR_ALGORITHM);
    }

    /**
     * Creates a new instance of <tt>RandomIVGenerator</tt> specifying a
     * secure random number generation algorithm.
     *
     * @since 1.9.3
     *
     */
    public RandomIVGenerator(String secureRandomAlgorithm) {
        super();
        try {
            this.random = SecureRandom.getInstance(secureRandomAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionInitializationException(e);
        }
    }

    /**
     * Generate a random IV of the specified length in bytes.
     *
     * @param length length in bytes.
     * @return the generated IV.
     */
    @Override
    public byte[] generateIV(int length) {
        byte[] iv = new byte[length / 8];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * This IV generator needs the salt to be included unencrypted in
     * encryption results, because of its being random. This method will always
     * return true.
     *
     * @return true
     */
    @Override
    public boolean includePlainIVInEncryptionResults() {
        return true;
    }
}


