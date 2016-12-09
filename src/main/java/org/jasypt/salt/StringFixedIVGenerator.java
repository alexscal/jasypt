package org.jasypt.salt;

import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

import java.io.UnsupportedEncodingException;

/**
 * <p>
 * String based implementation of {@link IVGenerator}, that will
 * always return the same IV. This IV is returned as bytes using the
 * specified charset for conversion (UTF-8 by default).
 * </p>
 * <p>
 * If the requested IV has a size in bytes smaller than the specified IV,
 * the first n bytes are returned. If it is larger, an exception is thrown.
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
public class StringFixedIVGenerator implements IVGenerator {

    private static final String DEFAULT_CHARSET = "UTF-8";

    private final String iv;
    private final String charset;
    private final byte[] ivBytes;



    /**
     * Creates a new instance of <tt>FixedStringIVGenerator</tt> using
     * the default charset.
     *
     * @param iv the specified salt.
     */
    public StringFixedIVGenerator(final String iv) {
        this(iv, null);
    }


    /**
     * Creates a new instance of <tt>FixedStringIVGenerator</tt>
     *
     * @param iv the specified salt.
     * @param charset the specified charset
     */
    public StringFixedIVGenerator(final String iv, final String charset) {
        super();
        CommonUtils.validateNotNull(iv, "IV cannot be set null");
        this.iv = iv;
        this.charset = (charset != null? charset : DEFAULT_CHARSET);
        try {
            this.ivBytes = this.iv.getBytes(this.charset);
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionInitializationException(
                    "Invalid charset specified: " + this.charset);
        }
    }


    /**
     * Return IV with the specified byte length.
     *
     * @param lengthBytes length in bytes.
     * @return the generated salt.
     */
    public byte[] generateIV(final int lengthBytes) {
        if (this.ivBytes.length < lengthBytes) {
            throw new EncryptionInitializationException(
                    "Requested IV larger than set");
        }
        final byte[] generatedIV = new byte[lengthBytes];
        System.arraycopy(this.ivBytes, 0, generatedIV, 0, lengthBytes);
        return generatedIV;
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