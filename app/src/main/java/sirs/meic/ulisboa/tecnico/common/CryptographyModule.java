package sirs.meic.ulisboa.tecnico.common;

import android.util.Base64;
import android.util.Log;

import com.google.common.io.Files;
import com.google.common.primitives.Ints;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static android.R.attr.data;


/**
 * Created by Belem on 01/12/2016.
 * This class is responsible for implementing the security mechanisms necessary for
 * enforcing the security requirements defined.
 */

public class CryptographyModule {
    private static final String TAG = "CryptographyModule";
    private static final String CA_PUBLIC_KEY_FILEPATH = "rootCA.key";
    private static final String SERVER_CERTIFICATE_FILEPATH = "server.cert";
    private static final String CLIENT_PRIVATE_KEY_FILEPATH = "client.key";


    final private static char[] hexArray = "0123456789ABCDEF".toCharArray();
    final private static int ITERATION_COUNT = 100;
    final public static int SECRET_KEY_ALGORITHM_BLOCK_SIZE = 32;

    final public static String SECRET_KEY__PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    final public static String SECRET_KEY_ALGORITHM = "AES/CBC/PKCS7Padding";

    final public static BigInteger DH_PUBLIC_VALUE_P = new BigInteger("1234567890", 16);
    final public static BigInteger DH_PUBLIC_VALUE_G = new BigInteger("1234567890", 16);

    private byte[] secretKey;
    private int counter; // used as IV, to ensure freshness
    private int incomingCounter;

    private Key DHPrivateKey;
    private Key DHPublicKey;
    private Key receivedPublicKey;

    public CryptographyModule() {
        counter = 0;
        incomingCounter = 0;
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            secretKey = digest.digest("Diffie-Hellman negotiated key".getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //generateDHKeys();
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
    public void incrCounter() { counter++;}

    public byte[] cipher(byte[] aBytes) throws InvalidKeyException {
        if (secretKey == null)
            throw new InvalidKeyException("SecretKey is undefined");

        final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
        return cipherAES(aBytes, keySpec);
    }
    public byte[] cipherDH(byte[] aBytes) throws InvalidKeyException {
        if (secretKey == null)
            throw new InvalidKeyException("Public key is undefined");

        return cipherAES(aBytes, DHPublicKey);
    }
    public byte[] cipherAES(byte[] aBytes, Key aKey) {
        if(aKey == null)
            throw new IllegalArgumentException(new NullPointerException("provided key is undefined."));

        byte[] cipheredBytes = null;
        ByteArrayOutputStream byteOutStream = null;

        try {

            byteOutStream = new ByteArrayOutputStream();
            byteOutStream.write(aBytes);
            byte[] plainBytes = byteOutStream.toByteArray();

            Cipher cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aKey, new IvParameterSpec(getInitVector()));
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
    public byte[] decipher(byte[] aBytes, byte[] iv) throws InvalidKeyException{
        if (secretKey == null)
            throw new InvalidKeyException("SecretKey is undefined");

        final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
        return decipherAES(aBytes, keySpec, iv);
    }
    public byte[] decipherAES(byte[] aBytes, Key aKey, byte[] iv) throws InvalidKeyException {
        if(aKey == null)
            throw new IllegalArgumentException(new NullPointerException("provided key is undefined."));

        byte[] plainBytes = null;

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aKey, new IvParameterSpec(iv));
            plainBytes = cipher.doFinal(aBytes);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return plainBytes;
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
            /* final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(1024);

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            DHprivateKey = keyPair.getPrivate();
            DHPublicKey = keyPair.getPublic(); */

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");

            DHParameterSpec param = new DHParameterSpec(DH_PUBLIC_VALUE_P, DH_PUBLIC_VALUE_P);
            kpg.initialize(param);
            KeyPair p = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("DH");
            DHPublicKey  = p.getPublic();
            DHPrivateKey = p.getPrivate();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
    public void generateDHCommonSecretKey() {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");

            keyAgreement.init(DHPrivateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            secretKey = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.e(TAG, "generateDHCommonSecretKey() Could not generate DH common session key exception", e);
        }
    }
    public byte[] hmac(byte[] aBytes) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(secretKey, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] hmac = sha256_HMAC.doFinal(aBytes);
        return hmac;
    }

    public byte[] getInitVector() {return String.format("%016d", counter).getBytes(); }
    public byte[] getDHPublicKeyEncoded() {
        return DHPublicKey.getEncoded();
    }
    public byte[] signRSAPrivateKey(byte[] aBytes) {

        byte[] keyBytes = null;
        try {
            keyBytes = Files.toByteArray(new File(CLIENT_PRIVATE_KEY_FILEPATH));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(spec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pk);

            return cipher.doFinal(aBytes);
        } catch (IOException e) {
            Log.e(TAG, "signRSAPrivateKey() IOException exception", e);
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "signRSAPrivateKey() InvalidKeySpecException exception", e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "signRSAPrivateKey() NoSuchAlgorithmException exception", e);
        } catch (BadPaddingException e) {
            Log.e(TAG, "signRSAPrivateKey() BadPaddingException exception", e);
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "signRSAPrivateKey() IllegalBlockSizeException exception", e);
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "signRSAPrivateKey() NoSuchPaddingException exception", e);
        } catch (InvalidKeyException e) {
            Log.e(TAG, "signRSAPrivateKey() InvalidKeyException exception", e);
        }
        return null;
    }

    public boolean isNonceValid(byte[] nonce) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

        String nonc = new String(getEncodingHex(nonce));

        Log.d(TAG, "Nonce " + nonc );
        if (nonc.equals(getEncodingHex(String.format("%016d", incomingCounter).getBytes()))) {
            Log.d(TAG, "Nonce " + nonc + " is valid");
            incomingCounter++;
            return true;
        } else {
            Log.d(TAG, "Invalid nonce " + nonc + "\nExpected: " + getEncodingHex(String.format("%016d", incomingCounter).getBytes()));
            return false;
        }
    }

    public byte[] storeDHReceivedKey(byte[] aBytes) {

        // Validate Signature of Server Certificate
        InputStream serverInput = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            serverInput = new BufferedInputStream(new FileInputStream(SERVER_CERTIFICATE_FILEPATH));
            X509Certificate serverCert = (X509Certificate) cf.generateCertificate(serverInput);
            serverCert.checkValidity();

            // READ CA PUBLIC KEY
            byte[] keyBytes = Files.toByteArray(new File(CA_PUBLIC_KEY_FILEPATH));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pk = kf.generatePublic(spec);
            serverCert.verify(pk);

            // If Certificate is ok, Then get public key from serverCert
            PublicKey serverRSAPubKey = serverCert.getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, serverRSAPubKey);

            return cipher.doFinal(aBytes);
        } catch (FileNotFoundException e) {
            Log.e(TAG, "storeDHReceivedKey() File not found exception", e);
        } catch (IOException e) {
            Log.e(TAG, "storeDHReceivedKey() IOException exception", e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "storeDHReceivedKey() NoSuchAlgorithmException exception", e);
        } catch (InvalidKeyException e) {
            Log.e(TAG, "storeDHReceivedKey() InvalidKeyException exception", e);
        } catch (SignatureException e) {
            Log.e(TAG, "storeDHReceivedKey() SignatureException exception", e);
        } catch (NoSuchProviderException e) {
            Log.e(TAG, "storeDHReceivedKey() NoSuchProviderException exception", e);
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "storeDHReceivedKey() InvalidKeySpecException exception", e);
        } catch (BadPaddingException e) {
            Log.e(TAG, "storeDHReceivedKey() BadPaddingException exception", e);
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "storeDHReceivedKey() IllegalBlockSizeException exception", e);
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "storeDHReceivedKey() NoSuchPaddingException exception", e);
        } catch (CertificateExpiredException e) {
            Log.e(TAG, "storeDHReceivedKey() Certificate Expired  exception", e);
        } catch (CertificateNotYetValidException e) {
            Log.e(TAG, "storeDHReceivedKey() CertificateNotYetValidException  exception", e);
        } catch (CertificateException e) {
            Log.e(TAG, "storeDHReceivedKey() Certificate  exception", e);
        } finally {
            if (serverInput != null) {
                try {
                    serverInput.close();
                } catch (IOException e) {
                    Log.e(TAG, "checkSignature() File Could not close crypto module server certificate inputstream", e);
                }
            }
        }
        return null;
    }
    public void receiveDHKey(byte[] aBytes) {
        //receivedPublicKey = storeDHReceivedKey(aBytes);

    }

    public boolean verifyMAC(byte[] originalMsg, byte[] sentDigest) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        byte[] originalMAC = hmac(originalMsg);

        Log.d(TAG, "validateMessage() ---- " + getEncodingHex(originalMAC));
        return Arrays.equals(originalMAC, sentDigest);
    }
}
