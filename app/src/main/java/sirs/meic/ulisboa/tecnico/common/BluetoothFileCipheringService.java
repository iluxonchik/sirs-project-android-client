package sirs.meic.ulisboa.tecnico.common;

import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Timer;


/**
 * Created by Belem on 03/12/2016.
 */

public class BluetoothFileCipheringService extends BluetoothCommunicatorService {
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

    public BluetoothFileCipheringService()   {
        super();
        this.counter = 0;
        cryptoModule = new CryptographyModule();
        // todo - enviar DH public key ao server
        tManager = new TokensManager();
    }

    public void init(String aUsername, String aPassword) throws InvalidKeySpecException,
                                            NoSuchAlgorithmException, NeedToLoginException {
        this.username = aUsername;
        hashPw = cryptoModule.applyPBKDeviation(aUsername, aPassword);
        try {
            tManager.loadToken(); // raised because it's required that the user inserts a pw
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void send(String aMsgType) {
        ByteArrayOutputStream bos =  new ByteArrayOutputStream();
        try {
            byte[] cipheredMsg = prepareRequest(aMsgType);

            bos.write(cipheredMsg);
            bos.write(cryptoModule.getInitVector());
            bos.write(cryptoModule.hash(cipheredMsg));
            write(encodeBase64inBytes(bos.toByteArray()));

            System.out.println("Sent message");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } finally {
            try {
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    protected void receive(byte[] aBuffer) {
        if(aBuffer != null && aBuffer.length > 0) {
            byte[] bytes = decodeBase64(aBuffer);
            String request = new String(bytes);

            System.out.println("Received request: " + request);
            switch(request) {
                case NEW_TOKEN:
                    updateToken(bytes, request.length());
                    break;
                case TOKEN_WRONG_ERR:
                case PWD_LOGIN_ERR:
                    send(PWD_LOGIN);
                    break;
                case NO_USR_ERR:
                    send(USR_REG);
                    try{
                        Thread.sleep(1000 * 2); // 2s
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    send(PWD_LOGIN);

            }
        }
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

}
