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
    final public static String SECRET_KEY_ALGORITHM = "AES/CBC/PKCS5Padding";

    final public static BigInteger DH_PUBLIC_VALUE_P = new BigInteger("2", 16);
    final public static BigInteger DH_PUBLIC_VALUE_G = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF", 16);

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

        SecretKeySpec skeySpec = new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
        return cipherAES(aBytes, skeySpec);
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
            Cipher cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aKey, new IvParameterSpec(getInitVector()));
            cipheredBytes = cipher.doFinal(aBytes);

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

        SecretKeySpec keySpec = new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
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
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");

            DHParameterSpec param = new DHParameterSpec(DH_PUBLIC_VALUE_P, DH_PUBLIC_VALUE_G);
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
    public void receiveDHKey(byte[] aBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        /* KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(storeDHReceivedKey(aBytes));
        receivedPublicKey = serverKeyFac.generatePublic(xKeySpec);
        generateDHCommonSecretKey(); */
    }

    public boolean verifyMAC(byte[] originalMsg, byte[] sentDigest) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        byte[] originalMAC = hmac(originalMsg);

        //Log.d(TAG, "validateMessage() ---- " + getEncodingHex(originalMAC));
        return Arrays.equals(originalMAC, sentDigest);
    }
}
