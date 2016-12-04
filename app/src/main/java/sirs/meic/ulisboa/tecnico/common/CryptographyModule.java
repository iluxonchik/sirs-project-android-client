package sirs.meic.ulisboa.tecnico.common;

import android.util.Base64;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static android.R.attr.publicKey;


/**
 * Created by Belem on 01/12/2016.
 * This class is responsible for implementing the security mechanisms necessary for
 * enforcing the security requirements defined.
 */

public class CryptographyModule {
    final private static char[] hexArray = "0123456789ABCDEF".toCharArray();
    final private static int ITERATION_COUNT = 100;
    final public static int SECRET_KEY_ALGORITHM_BLOCK_SIZE = 32;

    final public static String SECRET_KEY__PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    final public static String SECRET_KEY_ALGORITHM = "AES/CBC/PKCS5Padding";

    private byte[] secretKey;
    private byte[] initVector;

    private Key privateKey;
    private Key publicKey;
    private Key receivedPublicKey;

    public CryptographyModule() {
        // TODO - REMOVE DEFAULT SYM KEY
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // 32 * 8
            secretKey = keyGen.generateKey().getEncoded(); // by default

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        generateDHKeys();
    }


    private byte[] getKeyEncoded(Key key) {
        return key.getEncoded();
    }

    public byte[] applyPBKDeviation(String aUsername, String aPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(aUsername == null )
            throw new IllegalArgumentException(new NullPointerException("Username is null"));
        if(aPassword == null)
            throw new IllegalArgumentException(new NullPointerException("Password is null"));

        char[] pwChars = aPassword.toCharArray();
        byte[] salt = aUsername.getBytes();

        PBEKeySpec pbeKeySpec = new PBEKeySpec(pwChars, salt, ITERATION_COUNT, 32 * 8);

        SecretKeyFactory skf = SecretKeyFactory.getInstance(SECRET_KEY__PBKDF2_ALGORITHM);
        return skf.generateSecret(pbeKeySpec).getEncoded();
    }
    public byte[] cipher(byte[] aBytes) throws InvalidKeyException {
        if (secretKey == null)
            throw new InvalidKeyException("SecretKey is undefined");

        final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
        return cipherAES(aBytes, keySpec);
    }
    public byte[] cipherDH(byte[] aBytes) throws InvalidKeyException {
        if (publicKey == null)
            throw new InvalidKeyException("Public key is undefined");

        return cipherAES(aBytes, publicKey);
    }

    public byte[] cipherAES(byte[] aBytes, Key aKey) {
        if(aKey == null)
            throw new IllegalArgumentException(new NullPointerException("provided key is undefined."));

        byte[] cipheredBytes = null;
        ByteArrayOutputStream byteOutStream = null;

        try {
            byte[] nonce = getRandom();
            byte[] iv = initVector != null ? initVector : nonce;

            byteOutStream = new ByteArrayOutputStream();
            byteOutStream.write(aBytes);
            byteOutStream.write(nonce);

            byte[] plainBytes = byteOutStream.toByteArray();

            Cipher cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aKey, new IvParameterSpec(iv));
            cipheredBytes = cipher.doFinal(plainBytes);

        }  catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(byteOutStream != null)
                try {
                    byteOutStream.close();
                } catch (IOException e) {
                    // does nothing
                }
            return cipheredBytes;
        }
    }

    public String  getEncodingHex(byte[] aArg) throws InvalidKeySpecException, NoSuchAlgorithmException {
        char[] hexChars = new char[aArg.length * 2];
        for ( int j = 0; j < aArg.length; j++ ) {
            int v = aArg[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    public String  getEncodingBase64(byte[] aArg) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return Base64.encodeToString(aArg, Base64.DEFAULT);
    }

    // used to generate nonce values
    public byte[] getRandom() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[32];
        sr.nextBytes(random);

        return random;
    }

    public void generateDHKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(1024);

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    public void generateDHCommonSecretKey() {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            secretKey = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] getPublicKeyEncoded() {
        return publicKey.getEncoded();
    }
}
