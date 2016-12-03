package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import org.junit.Test;

import java.io.ByteArrayOutputStream;

import sirs.meic.ulisboa.tecnico.common.CryptographyModule;
import sirs.meic.ulisboa.tecnico.common.TokensManager;

import static org.junit.Assert.assertEquals;

/**
 * Created by Belem on 01/12/2016.
 */

public class TokensManagerTest {

    @Test
    public void storeToken_NoException_Success1() throws Exception {
        String random = "7bc857474ca037e6b7e9aea8f20775ea74bef7722572667d487d833a80bcc5bf";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(random.getBytes());
        TokensManager tm = new TokensManager();
        tm.storeToken(bos.toByteArray(), "tokens.txt");
    }

    @Test
    public void loadToken_NoException_Success1() throws Exception {
        TokensManager tm = new TokensManager();
        tm.loadToken("tokens.txt");
    }

    @Test
    public void storeAndLoad_Token_Success1() throws Exception {
        String random = "123";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(random.getBytes());
        TokensManager sc = new TokensManager();
        sc.storeToken(bos.toByteArray(), "test-storeAndLoadToken-1.txt");
        bos.reset();
        bos.write(sc.loadToken("test-storeAndLoadToken-1.txt"));
        assertEquals(random, bos.toString());

    }

}