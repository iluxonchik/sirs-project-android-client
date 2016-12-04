package sirs.meic.ulisboa.tecnico.common;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;


/**
 * Created by Belem on 03/12/2016.
 */

public class BluetoothFileCipheringService extends BluetoothCommunicatorService {
    public static final int DIFFIE_HELLMAN_MESSAGE = 0;
    public static final int TOKEN_RENEWAL_MESSAGE = 1;
    public static final int PROTOCOL_MESSAGE = 2;

    public static final String  DEFAULT_TOKEN_FILEPATH ="tokens.txt";

    private CryptographyModule cryptoModule;
    private TokensManager tManager;

    public BluetoothFileCipheringService()   {
        super();
        cryptoModule = new CryptographyModule();
        tManager = new TokensManager();
    }

    // todo - discuss protocol with illya
    public void send(int aMsgType) {
        switch (aMsgType) {
            case DIFFIE_HELLMAN_MESSAGE: // Send DH public key
                byte[] publicKey = cryptoModule.getPublicKeyEncoded();
                write(publicKey);
                break;
            case PROTOCOL_MESSAGE:
                byte[] token = tManager.getCurrentToken();

                if (token == null) {
                    token = new byte[]{}; // causes the server to reject and prompt for a new pws
                }
                try {
                    byte[] cipherBytes = cryptoModule.cipher(token);
                    write(cipherBytes);
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }
                break;
            default:
        }
    }
    // todo - think
    @Override
    protected void receive(byte[] aBuffer, int bytesRead, int bytesMax) {
        ByteArrayOutputStream msgBytes = new ByteArrayOutputStream();
        // TODO Protocol specification
        int msgType = DIFFIE_HELLMAN_MESSAGE;

        switch(msgType) {
            case DIFFIE_HELLMAN_MESSAGE: // received DH public key from server
                send(DIFFIE_HELLMAN_MESSAGE);
                cryptoModule.generateDHCommonSecretKey();
                break;
            case TOKEN_RENEWAL_MESSAGE:
                try {
                    tManager.storeToken(msgBytes.toByteArray(), DEFAULT_TOKEN_FILEPATH);

                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            default:

        }
        // DEFAULT - updateCryptoModule();
    }

    protected void updateCryptoModule() {

    }
}
