package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

// Common Package
import sirs.meic.ulisboa.tecnico.common.StrengthValidator;

public class MainActivity extends AppCompatActivity {

    private StrengthValidator validator;

    private EditText pwEditText;
    private EditText userEditText;
    private Button registerBttn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        registerBttn = (Button) findViewById(R.id.registerBttn);
        pwEditText = (EditText)findViewById(R.id.pwEditText);
        userEditText = (EditText)findViewById(R.id.userEditText);

        validator = new StrengthValidator();
    }

    public void signUp(View view) {
        String pwPattern = "[a-z][a-z0-9_-\\.]*";
        if(userEditText.getText().toString().isEmpty() || !validator.isInputSanitized(userEditText.getText().toString(), null)) {
            // TODO - Alert the user that the username mustn't
            finish();
        }
        else if (pwEditText.getText().toString().isEmpty() || !validator.validatePassword(pwEditText.getText().toString(), null)){
            // TODO - Alert the user that the username mustn't
            // TODO - Update a progress bar according to Score to show how weak the password is
            finish();
        }
        else {

        }
    }


}
