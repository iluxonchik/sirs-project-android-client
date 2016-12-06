package sirs.meic.ulisboa.tecnico.common;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;


/**
 * Created by Belem on 03/12/2016.
 */

public class BluetoothFileCipheringService extends BluetoothCommunicatorService {

    // Protocol specific tokens
    private static final String PWD_LOGIN = "log";

    private CryptographyModule cryptoModule;
    private FreshnessEnforcer freshnessModule;
    private TokensManager tManager;
    private String username;
    private byte[] hashPw;

    public BluetoothFileCipheringService()   {
        super();
        cryptoModule = new CryptographyModule();
        // todo - enviar DH public key ao server
        tManager = new TokensManager();
        freshnessModule = new FreshnessEnforcer();
    }

    public void send(int aMsgType) {

    }

    protected void receive(byte[] aBuffer) {
        if(aBuffer != null && aBuffer.length > 0) {
            String aString = new String(aBuffer);
        }


    }

    public void onLogin(String aUsername, String aPassword) throws InvalidKeySpecException,  NoSuchAlgorithmException {
        this.username = aUsername;
        hashPw = cryptoModule.applyPBKDeviation(aUsername, aPassword);
        byte[] cipheredMsg = null;

        ByteArrayOutputStream bos =  new ByteArrayOutputStream();
        try {
            bos.write(aUsername.getBytes());
            bos.write(hashPw);
            bos.write(PWD_LOGIN.getBytes());
            bos.write(PWD_LOGIN.length());
            cipheredMsg = cryptoModule.cipher(bos.toByteArray());

            bos.reset();
            bos.write(cipheredMsg);
            bos.write(cryptoModule.getInitVector());
            bos.write(cryptoModule.hash(cipheredMsg));
            write(bos.toByteArray()); // problems with base 64

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
    }

    public void onRegistration(String aUsername, String aPassword) throws InvalidKeySpecException, NoSuchAlgorithmException {
        onLogin(aUsername, aPassword);
    }



}
