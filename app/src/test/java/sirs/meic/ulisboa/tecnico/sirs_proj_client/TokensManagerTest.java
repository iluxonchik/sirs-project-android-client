package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import com.google.common.io.Files;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;

import sirs.meic.ulisboa.tecnico.common.CryptographyModule;
import sirs.meic.ulisboa.tecnico.common.NeedToLoginException;
import sirs.meic.ulisboa.tecnico.common.TokensManager;

import static org.junit.Assert.assertEquals;

/**
 * Created by Belem on 01/12/2016.
 */

public class TokensManagerTest {


    @Test
    public void loadToken_Exception_Success1() throws Exception, NeedToLoginException {
        //File.delete("tokens.txt");
        TokensManager tm = new TokensManager();
        tm.loadToken();
    }

    @Test
    public void storeToken_NoException_Success1() throws Exception {
        String random = "7bc857474ca037e6b7e9aea8f20775ea74bef7722572667d487d833a80bcc5bf";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(random.getBytes());
        TokensManager tm = new TokensManager();
        tm.storeToken(bos.toByteArray());
    }

    @Test
    public void loadToken_NoException_Success1() throws Exception, NeedToLoginException {
        TokensManager tm = new TokensManager();
        tm.loadToken();
    }

    @Test
    public void storeAndLoad_Token_Success1() throws Exception, NeedToLoginException {
        String random = "123";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(random.getBytes());
        TokensManager sc = new TokensManager();
        sc.storeToken(bos.toByteArray());
        bos.reset();
        bos.write(sc.loadToken());
        assertEquals(random, bos.toString());
    }

}