package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import org.junit.Test;
import org.junit.internal.runners.statements.ExpectException;

import sirs.meic.ulisboa.tecnico.common.StrengthValidator;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class StrengthValidatorTest {

    // Default Pattern (alphanumerical) validation
    @Test
    public void isInputSanitized_Default_NoInput_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String defaultInput = null;
        assertThat(sv.isInputSanitized(defaultInput, null), is(false));
    }

    @Test
    public void  Username_isInputSanitized_Default_AlphaOnly_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String defaultInput = "ola";
        assertThat(sv.isInputSanitized(defaultInput, null), is(true));
    }

    @Test
    public void Username_isInputSanitized_Default_EmptyString_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String defaultInput = "o*1lasd13sa";
        assertThat(sv.isInputSanitized(defaultInput, null), is(false));
    }

    @Test
    public void Username_isInputSanitized_Default_SpecialSyms_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String defaultInput = "o*1lasd13sa";
        assertThat(sv.isInputSanitized(defaultInput, null), is(false));
    }

    @Test
    public void Username_isInputSanitized_Default_FirstCharNumber_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String defaultInput = "1o3sa";
        assertThat(sv.isInputSanitized(defaultInput, null), is(false));
    }

    @Test
    public void Username_isInputSanitized_Default_UpperCase_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String defaultInput = "AAAA";
        assertThat(sv.isInputSanitized(defaultInput, null), is(true));
    }

    // Other Patterns Validation
    @Test
    public void Username_isInputSanitized_Pattern_NoPattern_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String patternReg = null;
        String defaultInput = "aaaaaa";
        assertThat(sv.isInputSanitized(defaultInput, null), is(true));
    }

    @Test
    public void Username_isInputSanitized_Pattern_NoPattern_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String patternReg = null;
        String defaultInput = "1aaaaaa";
        assertThat(sv.isInputSanitized(defaultInput, null), is(false));
    }

    @Test
    public void Username_isInputSanitized_Pattern_EmptyPattern_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String patternReg = "";
        String defaultInput = "aaaa";
        assertThat(sv.isInputSanitized(defaultInput, patternReg), is(false));
    }

    @Test
    public void Username_isInputSanitized_Pattern_EverySym_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String patternReg = ".*";
        String defaultInput = "1#.";
        assertThat(sv.isInputSanitized(defaultInput, patternReg), is(true));
    }

    @Test
    public void Username_isInputSanitized_Pattern_EscapedDot_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String patternReg = "\\.+";
        String defaultInput = "..";
        assertThat(sv.isInputSanitized(defaultInput, patternReg), is(true));
    }

    // Password Strength Testing

    // Null password
    @Test (expected = IllegalArgumentException.class)
    public void Password_getPasswordScore_NoPassword_ThrowsException() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = null;
        sv.getPasswordScore(password);
    }

    // Empty Password
    @Test
    public void Password_getPasswordScore_EmptyPassword_Retuns0() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "";
        assertThat(sv.getPasswordScore(password), is(0));
    }

    // Very Weak (0)
    @Test
    public void Password_getPasswordScore_VeryWeak0_returnsZero() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "123456789";
        assertThat(sv.getPasswordScore(password), is(0));
    }

    @Test
    public void Password_getPasswordScore_VeryWeak1_returnsZero() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "asdfghjkl";
        assertThat(sv.getPasswordScore(password), is(0));
    }

    @Test
    public void Password_getPasswordScore_VeryWeak2_returnsZero() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "qwerty123";
        assertThat(sv.getPasswordScore(password), is(0));
    }


    @Test
    public void Password_getPasswordScore_VeryWeak3_returnsZero() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "password";
        assertThat(sv.getPasswordScore(password), is(0));
    }

    // Weak (1)
    @Test
    public void Password_getPasswordScore_Weak0_returnsOne() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "catarina8";
        assertThat(sv.getPasswordScore(password), is(1));
    }

    @Test
    public void Password_getPasswordScore_Weak1_returnsOne() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "lovecats";
        assertThat(sv.getPasswordScore(password), is(1));
    }

    // Medium (2)
    @Test
    public void Password_getPasswordScore_Medium0_returnsTwo() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "123PassworD123";
        assertThat(sv.getPasswordScore(password), is(2));
    }
    // Strong (3)
    @Test
    public void Password_getPasswordScore_Strong0_returnsThree() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "LoveCats3";
        assertThat(sv.getPasswordScore(password), is(3));
    }

    // Very Strong (4)
    @Test
    public void Password_getPasswordScore_VeryStrong0_returnsFour() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "D_1ckau13cDZoAMjd";
        assertThat(sv.getPasswordScore(password), is(4));
    }

    // Validate Passwords (:
    // Null password
    @Test (expected = IllegalArgumentException.class)
    public void Password_ValidatePassword_NoPassword_ThrowsException() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = null;
        String pattern = null;
        sv.validatePassword(password, pattern);
    }

    @Test (expected = IllegalArgumentException.class)
    public void Password_ValidatePassword_NoPassword_EmptyPattern_ThrowsException() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = null;
        String pattern = "";
        sv.validatePassword(password, pattern);
    }

    // Empty Password
    @Test
    public void Password_ValidatePassword_EmptyPassword_RetunsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "";
        String pattern = null;
        assertThat(sv.validatePassword(password, pattern), is(false));
    }

    // Very Weak (0)
    @Test
    public void Password_validatePassword_VeryWeak0_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "123456789";
        String pattern = null;
        assertThat(sv.validatePassword(password, pattern), is(false));
    }

    // Weak (1)
    @Test
    public void Password_validatePassword_Weak1_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "lovecats";
        String pattern = null;
        assertThat(sv.validatePassword(password, pattern), is(false));
    }


    // Medium (2)
    @Test
    public void Password_validatePassword_Default_Medium0_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "123PassworD123";
        String pattern = null;
        // default pattern does not allow numbers as the first char
        assertThat(sv.validatePassword(password, pattern), is(false));
    }

    @Test
    public void Password_validatePassword_Medium0_returnsFalse() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "123PassworD123";
        String pattern = "[a-z0-9\\._-,]*";
        // default pattern does not allow numbers as the first char
        assertThat(sv.validatePassword(password, pattern), is(false));
    }

    // Strong (3)
    @Test
    public void Password_validatePassword_Strong0_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "LoveCats3";
        String pattern = null;
        assertThat(sv.validatePassword(password, pattern), is(true));
    }

    // Very Strong (4)
    @Test
    public void Password_validatePassword_VeryStrong0_returnsTrue() throws Exception {
        StrengthValidator sv = new StrengthValidator();
        String password = "D_1ckau13cDZoAMjd";
        String pattern = null;
        assertThat(sv.validatePassword(password, pattern), is(true));
    }


}