package sirs.meic.ulisboa.tecnico.common;

import android.util.Base64;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;



/**
 * Created by Belem on 01/12/2016.
 * This class is responsible for implementing the security mechanisms necessary for
 * enforcing the security requirements defined.
 */

public class SecureCommunicator {
    private static final int ITERATION_COUNT = 100;
    private static final String SECRET_KEY__PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    private byte[] pwHash;

    public SecureCommunicator () {
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

    public void generateHash(String aUsername, String aPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(aUsername == null )
            throw new IllegalArgumentException(new NullPointerException("Username is null"));
        if(aPassword == null)
            throw new IllegalArgumentException(new NullPointerException("Password is null"));

        char[] pwChars = aPassword.toCharArray();
        byte[] salt = aUsername.getBytes();

        //BEKeySpec pbeKeySpec = new PBEKeySpec(pwChars, salt, 1, 256);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(pwChars, salt, ITERATION_COUNT, 32 * 8);

        SecretKeyFactory skf = SecretKeyFactory.getInstance(SECRET_KEY__PBKDF2_ALGORITHM);
        pwHash = skf.generateSecret(pbeKeySpec).getEncoded();
    }


}
