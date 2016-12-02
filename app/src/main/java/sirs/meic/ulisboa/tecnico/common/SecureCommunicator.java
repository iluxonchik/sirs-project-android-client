package sirs.meic.ulisboa.tecnico.common;

import android.util.Base64;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLHandshakeException;


/**
 * Created by Belem on 01/12/2016.
 * This class is responsible for implementing the security mechanisms necessary for
 * enforcing the security requirements defined.
 */

public class SecureCommunicator {
    private static final int ITERATION_COUNT = 100;
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static final String SECRET_KEY__PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final String PUBLIC_KEY_ALGORITHM = "RSA";


    private byte[] pwHash;
    private String keysFilePath;

    public SecureCommunicator (String aKeysFilePath) {
        this.keysFilePath = aKeysFilePath;
    }
    public void   generateHash(String aUsername, String aPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(aUsername == null )
            throw new IllegalArgumentException(new NullPointerException("Username is null"));
        if(aPassword == null)
            throw new IllegalArgumentException(new NullPointerException("Password is null"));

        char[] pwChars = aPassword.toCharArray();
        byte[] salt = aUsername.getBytes();

        PBEKeySpec pbeKeySpec = new PBEKeySpec(pwChars, salt, ITERATION_COUNT, 32 * 8);

        SecretKeyFactory skf = SecretKeyFactory.getInstance(SECRET_KEY__PBKDF2_ALGORITHM);
        pwHash = skf.generateSecret(pbeKeySpec).getEncoded();
    }
    public String getGeneratedHashBase64() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return Base64.encodeToString(pwHash, Base64.DEFAULT);
    }
    public String getGeneratedHashHex() throws InvalidKeySpecException, NoSuchAlgorithmException {
        char[] hexChars = new char[pwHash.length * 2];
        for ( int j = 0; j < pwHash.length; j++ ) {
            int v = pwHash[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public String cipherMessageBase64(String aMessage, String aKeyFilepath) {
        return Base64.encodeToString(this.cipherMessage(aMessage, aKeyFilepath), Base64.DEFAULT);
    }
    public byte[] cipherMessage(String aMessage, String aKeyFilepath) {
        if(aKeyFilepath == null || aKeyFilepath.isEmpty())
            throw new IllegalArgumentException("aKeyFilepath is either null or empty.");

        InputStream inStream = null;
        ByteArrayOutputStream byteOutStream = null;

        try {
            inStream = new BufferedInputStream(new FileInputStream(aKeyFilepath));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

            PublicKey publicKey = cert.getPublicKey();
            byte[]  message = aMessage.getBytes();
            byte[] nonce = getRandom();

            byteOutStream = new ByteArrayOutputStream();
            byteOutStream.write(message);
            byteOutStream.write(pwHash);
            byteOutStream.write(nonce);

            byte[] plainBytes = byteOutStream.toByteArray();

            Cipher cipher = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipheredBytes = cipher.doFinal(plainBytes);

            return cipheredBytes;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } finally {
            if(inStream != null)
                try {
                    inStream.close();
                } catch (IOException e) {
                    // does nothing
                }
            if(byteOutStream != null)
                try {
                    byteOutStream.close();
                } catch (IOException e) {
                    // does nothing
                }

        }

    }

    // used to generate nonce values
    public byte[] getRandom() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        sr.nextBytes(random);

        return random;
    }

}
