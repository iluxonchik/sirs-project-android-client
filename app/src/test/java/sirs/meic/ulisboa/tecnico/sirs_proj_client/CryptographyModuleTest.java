package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import org.junit.Test;

import java.io.ByteArrayOutputStream;

import sirs.meic.ulisboa.tecnico.common.CryptographyModule;

import static org.junit.Assert.assertEquals;

/**
 * Created by Belem on 01/12/2016.
 */

public class CryptographyModuleTest {

    // Deviation function
    @Test (expected = IllegalArgumentException.class)
    public void applyPBKDeviation_NullArgs0_ThrowException() throws Exception {
        String username = null;
        String password = null;
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    @Test (expected = IllegalArgumentException.class)
    public void applyPBKDeviation_NullArgs1_ThrowException() throws Exception {
        String username = "HelloWorld";
        String password = null;
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    @Test (expected = IllegalArgumentException.class)
    public void applyPBKDeviation_NullArgs2_ThrowException() throws Exception {
        String username = null;
        String password = "ThisIsAPassword";
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    @Test (expected = IllegalArgumentException.class)
    public void applyPBKDeviation_EmptyUsername_ThrowException() throws Exception {
        String username = "";
        String password = "ThisIsAPassword";
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    // Online pbkdf2 : http://www.neurotechnics.com/tools/pbkdf2
    @Test
    public void applyPBKDeviation_Success0_returnsTrue() throws Exception {
        String username = "catarina";
        String password = "catarina";
        String resultFor100Iterations = "9f1af7f457b93e87fc685e535994904e22afcfc7c890a035adf94b2ebd360804";
        CryptographyModule sc = new CryptographyModule();
        assertEquals(sc.getEncodingHex(sc.applyPBKDeviation(username, password)).toUpperCase(), resultFor100Iterations.toUpperCase());
    }

    @Test
    public void applyPBKDeviation_Success1_returnsTrue() throws Exception {
        String username = "catarina";
        String password = "password";
        String resultFor100Iterations = "7bc857474ca037e6b7e9aea8f20775ea74bef7722572667d487d833a80bcc5bf";
        CryptographyModule sc = new CryptographyModule();
        assertEquals(sc.getEncodingHex(sc.applyPBKDeviation(username, password)).toUpperCase(), resultFor100Iterations.toUpperCase());
    }
}