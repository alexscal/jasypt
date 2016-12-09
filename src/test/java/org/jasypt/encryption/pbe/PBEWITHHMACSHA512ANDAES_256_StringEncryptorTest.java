package org.jasypt.encryption.pbe;

public class PBEWITHHMACSHA512ANDAES_256_StringEncryptorTest extends AbstractPBEStringEncryptorTest {


    @Override
    protected PBEStringEncryptor createPBEStringEncryptor() {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
        return encryptor;
    }
}
