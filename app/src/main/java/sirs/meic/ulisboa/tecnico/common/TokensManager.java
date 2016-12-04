package sirs.meic.ulisboa.tecnico.common;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by Belem on 03/12/2016.
 */
public class TokensManager {
    private byte[] currentToken;

    public TokensManager() {}

    byte[] getCurrentToken() {
        return currentToken;
    }
    // Store Token to file
    public void storeToken(byte[] aToken, String aFilepath) throws IOException {
        OutputStream output = null;
        try {
            output = new BufferedOutputStream(new FileOutputStream(aFilepath));
            output.write(aToken);
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    // does nothing
                }
            }
        }
    }
    public byte[] loadToken(String aFilePath) throws IOException {
        InputStream input = null;
        try {
            input = new BufferedInputStream(new FileInputStream(aFilePath));
            byte[] token = new byte[input.available()];
            input.read(token);
            currentToken = token;
            return token;
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    // does nothing
                }
            }
        }
    }
}
