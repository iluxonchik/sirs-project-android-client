package sirs.meic.ulisboa.tecnico.common;

import com.nulabinc.zxcvbn.Feedback;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by Belem on 01/12/2016.
 * This class is a Wrapper of the ZXCVBN which is a Password strength validator
 * Check on the library's detail: https://github.com/nulab/zxcvbn4j
 * I've also added up a isInputSanitized method to validate inputs
 */

public class StrengthValidator {
    private static final String DEFAULT_SANITIZED_PATTERN = "[a-z_][a-z0-9_]*";
    private static final int WEAK_PASSWORD_LEVEL = 2;
    private Zxcvbn zxcvbn;

    public StrengthValidator() {
        zxcvbn = new Zxcvbn();
       }
    // Score range: [0-4]
    public int getPasswordScore(String aPassword) {
        Strength strength = zxcvbn.measure(aPassword);
        return strength != null ? strength.getScore() : null;
    }
    public boolean isInputSanitized (String aInput, String aPattern) {
        Pattern pattern = Pattern.compile(aPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(aInput);
        return matcher.matches(); //true only if entire region sequence matches the pattern
    }

    // Consider a weak password's level < WEAK_PASSWORD_LEVEL
    public boolean validatePassword(String aPassword, String aPattern) {
        int pwScore = getPasswordScore(aPassword);
        return pwScore >= WEAK_PASSWORD_LEVEL && isInputSanitized(aPassword, ((aPattern == null || aPattern.isEmpty()) ? DEFAULT_SANITIZED_PATTERN : aPattern));
    }
    public HashMap<String, List<String>> getPasswordFeedback(String aPassword) {
        HashMap<String, List<String>> feedbackHM = new HashMap<>();
        Feedback feedback;

        Strength strength = zxcvbn.measure(aPassword);

        if (strength != null && (feedback = strength.getFeedback()) != null) {
            feedbackHM.put("suggestions", feedback.getSuggestions());

            List<String> warningsList = new ArrayList<String>();
            warningsList.add(feedback.getWarning());

            feedbackHM.put("warnings", warningsList);
        }
        return feedbackHM;
    }
    public double estimateComplexity(String aPassword) {
        Strength strength = zxcvbn.measure(aPassword);
        return strength!= null ? strength.getGuesses() : null;
    }
}
