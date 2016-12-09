package sirs.meic.ulisboa.tecnico.common;

import android.os.Handler;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


/**
 * Created by Belem on 03/12/2016.
 */

public class BluetoothFileCipheringService extends BluetoothCommunicatorService {
    private static final String TAG = "BluetoothFileCiphering";
    private static final String DIFFIE_HELLMAN_KEY = "DH_Key";

    // Protocol specific Messages
    // Protocol specific sent tokens
    private static final String PWD_LOGIN = "log";
    private static final String USR_REG = "reg";
    private static final String DECRYPT = "dec";

    // Protocol specific received tokens
    private static final String TOKEN_WRONG_ERR ="wrong_token";
    private static final String NEW_TOKEN = "new_token";
    private static final String PWD_LOGIN_ERR = "log_err";
    private static final String NO_USR_ERR = "usr_err";

    private CryptographyModule cryptoModule;
    private TokensManager tManager;
    private String username;
    private byte[] hashPw;
    private int counter;

    public BluetoothFileCipheringService(Handler handler)   {
        super(handler);
        this.counter = 0;
        cryptoModule = new CryptographyModule();
        tManager = new TokensManager();
    }

    public void login(String aUsername, String aPassword) throws InvalidKeySpecException,
                                            NoSuchAlgorithmException, NeedToLoginException {
        this.username = "thegame"; // aUsername;
        this.hashPw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(); // hashPw = cryptoModule.applyPBKDeviation(aUsername, aPassword);
        send(PWD_LOGIN);
        /*
        try {
            tManager.loadToken(); // NeedToLoginException raised because it's required that the user inserts a pw
        } catch (IOException e) {
            e.printStackTrace();
        }*/
    }

    public void init (){
        /*byte[] dhPublicKey = cryptoModule.signRSAPrivateKey(cryptoModule.getDHPublicKeyEncoded());
        try {
            write(encodeBase64inBytes(dhPublicKey));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }*/
    }

    public void send(String aMsgType) {
        ByteArrayOutputStream bos =  new ByteArrayOutputStream();
        ByteArrayOutputStream bos2 =  new ByteArrayOutputStream();
        ByteArrayOutputStream bos3 =  new ByteArrayOutputStream();
        try {

            byte[] cipheredMsg = prepareRequest(aMsgType);

            bos.write(cipheredMsg);
            bos.write(cryptoModule.getInitVector());

            bos2.write(aMsgType.getBytes());
            if(aMsgType.contains(PWD_LOGIN)){
                bos2.write(username.getBytes());
                bos2.write(hashPw);
                Log.d(TAG, "initvector: " + cryptoModule.getEncodingHex(cryptoModule.getInitVector()));
            }
            bos3.write(bos2.toByteArray());
            bos3.write(cryptoModule.getInitVector());
            bos.write(cryptoModule.hmac(bos3.toByteArray()));

            write(encodeBase64inBytes(bos.toByteArray()));

            cryptoModule.incrCounter();
            Log.d(TAG, "Sent message");
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "send() Problems finding algorithms ", e);
        } catch (IOException e) {
            Log.e(TAG, "send() Problems in streams ", e);
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "send() Problems in keys specifications ", e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } finally {
            try {
                bos.close();
            } catch (IOException e) {
                Log.e(TAG, "send() Problems in closing streams ", e);
            }
        }
    }

    protected void receive(byte[] aBuffer) { // TODO - RECEBER CHAVE DH
        Log.d(TAG, "received message");
        if(aBuffer != null && aBuffer.length > 0) {
            byte[] bytes = decodeBase64(aBuffer);
            //Log.d(TAG, "Received request: " + bytes);
            byte[] requestBytes =  null;
            String request = "";

            try {
                if(validateMessage(bytes)){
                    int requestLength = bytes.length - 16 - 32;
                    byte[] nonce = Arrays.copyOfRange(bytes, requestLength, requestLength + 16);

                    requestBytes = getDecipheredRequest(bytes, nonce);
                    request = new String(cryptoModule.getEncodingHex(requestBytes));
                    Log.d(TAG, "Received request: " + request);

                    if (request.contains(NEW_TOKEN)) {
                        byte[] token = Arrays.copyOfRange(requestBytes, NEW_TOKEN.length(), request.length());
                        Log.d(TAG, "token: " + token.toString());
                        updateToken(token, request.length());
                        Log.d(TAG, "updated token: " );
                    }
                    else if (request.contains(TOKEN_WRONG_ERR) || request.contains(PWD_LOGIN_ERR)) {
                        send(PWD_LOGIN);
                    }
                    else if (request.contains(NO_USR_ERR)) {
                        send(USR_REG);
                        try{
                            Thread.sleep(1000 * 2); // 2s
                        } catch (InterruptedException e) {
                        }
                        send(PWD_LOGIN);
                    }
                    else {
                        Log.d(TAG, "REQUEST NOT RECOGNIZED");
                    }
                }
            } catch (InvalidKeyException e) {Log.e(TAG, "receive() Couldn't validate msg ", e); return;
            } catch (IOException e) {Log.e(TAG, "receive() Couldn't validate msg", e); return;
            } catch (NoSuchAlgorithmException e) {Log.e(TAG, "receive() Couldn't validate msg ", e); return;
            } catch (InvalidKeySpecException e) {Log.e(TAG, "receive() Couldn't validate msg ", e); return;
            }

        }
    }

    private boolean validateMessage(byte[] bytes) throws InvalidKeyException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        int requestLength = bytes.length - 16 - 32;
        Log.d(TAG, "validateMessage() " + cryptoModule.getEncodingHex(bytes));
        byte[] request = Arrays.copyOfRange(bytes, 0, requestLength); //IV || HMACSHA256
        Log.d(TAG, "validateMessage() " + cryptoModule.getEncodingHex(request));
        byte[] nonce = Arrays.copyOfRange(bytes, requestLength, requestLength + 16);
        Log.d(TAG, "validateMessage() length: " + nonce.length + " :nonce(HEX): " + cryptoModule.getEncodingHex(nonce));
        byte[] mac = Arrays.copyOfRange(bytes, requestLength + 16, requestLength + 16 + 32);
        Log.d(TAG, "validateMessage() " + cryptoModule.getEncodingHex(mac));

        if (!cryptoModule.isNonceValid(nonce)) {
            return false;
        }
        byte[] decipherMsg = cryptoModule.decipher(request, nonce);
        Log.d(TAG, "deciphered msg " + cryptoModule.getEncodingHex(decipherMsg));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(decipherMsg);
        bos.write(nonce);
        Log.d(TAG, "validateMessage() ---- ");
        if (!cryptoModule.verifyMAC(bos.toByteArray(), mac)) {
            Log.d(TAG, "validateMessage() ---- ");
            return false;
        }

        return true;
    }

    private void updateToken(byte[] aToken, int offset) {
        if(aToken != null && aToken.length > offset) {
            System.out.println("Updating token");
            byte[] token = new byte[aToken.length-3];
            try {
                ByteBuffer.wrap(aToken, offset, aToken.length - offset).get(token);
                if (tManager != null) {
                    tManager.storeToken(token);
                } else {
                    // shouldnt happen
                    System.out.println("Unexpected exception updating token");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
            }

    private byte[] prepareRequest(String aMsgType) throws InvalidKeySpecException, NoSuchAlgorithmException {
        switch(aMsgType) {
            case USR_REG:
                System.out.println("Prepared REG message");
                return getLoginOrRegRequest(aMsgType);
            case PWD_LOGIN:
                System.out.println("Prepared LOGIN message");
                return getLoginOrRegRequest(aMsgType);
            case DECRYPT:
                System.out.println("Preparing DECRYPT message");
                return getDecryptRequest();
            default:
                System.out.println("Unsupported request specified");
                return null;
        }
    }

    public byte[] getLoginOrRegRequest(String aMsgType) throws InvalidKeySpecException,  NoSuchAlgorithmException {

        ByteArrayOutputStream bos =  new ByteArrayOutputStream();
        try {
            System.out.println(aMsgType + " Request...");
            bos.write(aMsgType.getBytes());
            bos.write(username.getBytes());
            bos.write(hashPw);
            return cryptoModule.cipher(bos.toByteArray());

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public byte[] getDecryptRequest() throws InvalidKeySpecException,  NoSuchAlgorithmException {

        ByteArrayOutputStream bos =  new ByteArrayOutputStream();
        try {
            System.out.println("Decrypt Request...");
            bos.write(PWD_LOGIN.getBytes());
            bos.write(username.getBytes());
            bos.write(hashPw);
            byte[] token = tManager.getLastSeenToken();
            bos.write(token);
            String tokenLen = String.format("%03d", token.length);
            System.out.println("Token: " + encodeBase64(token) + " Token Len: " + tokenLen);
            bos.write(tokenLen.getBytes());
            return cryptoModule.cipher(bos.toByteArray());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public byte[] encodeBase64inBytes(byte[] aByteArr) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return encodeBase64(aByteArr).getBytes();
    }
    public String encodeBase64(byte[] aByteArr) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return cryptoModule.getEncodingBase64(aByteArr);
    }

    public byte[] decodeBase64(byte[] aByteArr) {
        return Base64.decode(aByteArr, Base64.DEFAULT);
    }

    public byte[] getDecipheredRequest(byte[] aBytes, byte[] nonce) throws InvalidKeyException, IOException {
        int requestLength = aBytes.length - 16 - 256;
        byte[] request = Arrays.copyOfRange(aBytes, 0, requestLength);
        return cryptoModule.decipher(request, nonce);

    }
}
