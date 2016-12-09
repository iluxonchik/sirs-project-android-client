package sirs.meic.ulisboa.tecnico.sirs_proj_client;


import android.util.Log;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


import sirs.meic.ulisboa.tecnico.common.CryptographyModule;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

/**
 * Created by Belem on 01/12/2016.
 */

public class CryptographyModuleTest {

    // Deviation function
    @Test(expected = IllegalArgumentException.class)
    public void applyPBKDeviation_NullArgs0_ThrowException() throws Exception {
        String username = null;
        String password = null;
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    @Test(expected = IllegalArgumentException.class)
    public void applyPBKDeviation_NullArgs1_ThrowException() throws Exception {
        String username = "HelloWorld";
        String password = null;
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    @Test(expected = IllegalArgumentException.class)
    public void applyPBKDeviation_NullArgs2_ThrowException() throws Exception {
        String username = null;
        String password = "ThisIsAPassword";
        CryptographyModule sc = new CryptographyModule();
        sc.getEncodingBase64(sc.applyPBKDeviation(username, password));
    }

    @Test(expected = IllegalArgumentException.class)
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

    @Test
    public void verifyCipherDecipher_NotEqualsResult() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] plainText = "QueroEncriptarIsto".getBytes("UTF-8");
        CryptographyModule cm = new CryptographyModule();
        byte[] result = cm.cipher(plainText);

        assertThat(Arrays.equals(result, cm.decipher(result, cm.getInitVector())), is(false));
    }

    @Test
    public void verifyCipherDecipher_EqualsResult() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] plainText = "QueroEncriptarIsto".getBytes("UTF-8");
        CryptographyModule cm = new CryptographyModule();
        byte[] result = cm.cipher(plainText);

        assertThat(Arrays.equals(plainText, cm.decipher(result, cm.getInitVector())), is(true));
    }

    @Test
    public void verifyCipher_Success1() throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        String cifra = "1A012F28FAA5F80327120F052A57F5141273CF0910DD3CEC233EB84B9802EBD30B293B01030C396F2F45F7989F3E35F469EB39A8F1E1306506712EF0FE4DA1CC";
        CryptographyModule cm = new CryptographyModule();
        String resultHexa = cm.getEncodingHex(cm.decipher(cifra.getBytes(), cm.getInitVector()));
        assertEquals(resultHexa, "746F6B5F6E6577834146AEF05EB4BB02A66E739D089EDED96C66376277307760BF647ED140E1CF69748CBF38A72900D07D379112C160B5");

    }
}