package sirs.meic.ulisboa.tecnico.common;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;

/**
 * Created by Belem on 03/12/2016.
 */

public abstract class Communicator {
    final public static String  DEFAULT_TOKEN_FILEPATH ="tokens.txt";
    final public static String  SYM_KEY_ALGORITHM = "AES";
    final public static int     SYM_KEY_SIZE = 256;

    private CryptographyModule cryptoModule;
    private TokensManager tManager;

    public Communicator() {
        try {

            KeyGenerator keyGen = KeyGenerator.getInstance(SYM_KEY_ALGORITHM);
            keyGen.init(SYM_KEY_SIZE);
            Key key = keyGen.generateKey();

            cryptoModule = new CryptographyModule(key);
            tManager = new TokensManager();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}
