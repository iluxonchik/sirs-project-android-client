package sirs.meic.ulisboa.tecnico.common;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Created by Belem on 03/12/2016.
 */
public class TokensManager extends FilesManager {

    public static final String  DEFAULT_TOKEN_FILEPATH ="tokens.txt";

    public TokensManager() {}

    byte[] getLastSeenToken() {
        return getLastSeenArg();
    }

    public void storeToken(byte[] aToken) throws IOException {
       super.store(aToken, DEFAULT_TOKEN_FILEPATH);
    }
    public byte[] loadToken() throws IOException {
        return super.load(DEFAULT_TOKEN_FILEPATH);
    }

}
