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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;


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

    private Key secretKey;
    private byte[] initVector;

    public CryptographyModule() {
        this(null);
    }
    public CryptographyModule (Key aSecretKey){
        this.secretKey = aSecretKey;
        this.initVector = null;
    }

    public void setSecurityParameters(byte[] aIV){
        this.initVector = aIV;
    }
    public void setSecurityParameters(Key aSecretKey){
        this.secretKey = aSecretKey;
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
    public byte[] cipherAES(byte[] aBytes) {
        if(secretKey == null)
            throw new IllegalArgumentException(new NullPointerException("secret key is undefined."));

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
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
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

}