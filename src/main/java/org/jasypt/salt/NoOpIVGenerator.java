package org.jasypt.salt;

/**
 * <p>
 * SNoOp implementation of {@link IVGenerator}, when you don't want to use an IV
 * for encryption.  This is useful if you need to decrypt an old password that was 
 * encrypted in an older version ofJasypt before there were IV's in JDK8.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 *
 * @since 1.9.3
 *
 * @author Melloware (mellowaredev@gmail.com)
 *
 */
public class NoOpIVGenerator implements IVGenerator {

    /**
     * Return IV with the specified byte length.
     *
     * @param lengthBytes length in bytes.
     * @return the generated salt.
     */ 
    @Override
    public byte[] generateIV(final int lengthBytes) {
        return null;
    }

    /**
     * As this salt generator provides a fixed IV, its inclusion
     * unencrypted in encryption results
     * is not necessary, and in fact not desirable (so that it remains hidden).
     *
     * @return false
     */
    @Override
    public boolean includePlainIVInEncryptionResults() {
        return false;
    }

}
