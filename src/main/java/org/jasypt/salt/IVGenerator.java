package org.jasypt.salt;

/**
 * <p>
 * Common interface for all IV generators which can be applied in digest
 * or encryption operations.
 * </p>
 * <p>
 * <b>Every implementation of this interface must be thread-safe</b>.
 * </p>
 *
 * @since 1.9.3
 *
 * @author Alex Scal
 *
 */
public interface IVGenerator {

    /**
     * <p>
     * This method will be called for requesting the generation of a new
     * IV of the specified length.
     * </p>
     *
     * @param length the requested length for the IV.
     * @return the generated IV.
     */
    byte[] generateIV(int length);


    /**
     * <p>
     * Determines if the digests and encrypted messages created with a
     * specific IV generator will include (prepended) the unencrypted
     * IV itself, so that it can be used for matching and decryption
     * operations.
     * </p>
     * <p>
     * Generally, including the IV unencrypted in encryption results will
     * be mandatory for randomly generated IVs, or for those generated in a
     * non-predictable manner.
     * Otherwise, digest matching and decryption operations will always fail.
     * </p>
     *
     * @return whether the plain (unencrypted) IV has to be included in
     *         encryption results or not.
     */
    public boolean includePlainIVInEncryptionResults();

}
