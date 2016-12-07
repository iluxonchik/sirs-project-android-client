package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.content.Intent;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import sirs.meic.ulisboa.tecnico.common.BluetoothFileCipheringService;
import sirs.meic.ulisboa.tecnico.common.Constants;
import sirs.meic.ulisboa.tecnico.common.StrengthValidator;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private static final String ADDRESS = "24:0A:64:91:D4:D0";

    // Intent Request Codes
    private static final int REQUEST_ENABLE_BT = 1;

    private EditText etUsername;
    private EditText etPassword;
    private Button bLogin;
    private StrengthValidator validator;

    /**
     * Local Bluetooth Adapter
     */

    private BluetoothAdapter mBluetoothAdapter = null;
    private BluetoothFileCipheringService mFileCipheringService = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);



        etUsername = (EditText)findViewById(R.id.etUsername);
        etPassword = (EditText)findViewById(R.id.etPassword);
        bLogin = (Button) findViewById(R.id.bLogin);

        validator = new StrengthValidator();

        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        if (mBluetoothAdapter == null) {
            Toast.makeText(this, R.string.bt_not_enabled_leaving, Toast.LENGTH_SHORT).show();
            this.finish();

        }

        bLogin.setOnClickListener( new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(validate())
                    login();
                else
                    Log.d(TAG, "No login");
            }
        });
    }

    public boolean validate() {
        Log.d(TAG, "Validate");

        Log.d(TAG, "Validating username " + etUsername.getText().toString());
        Log.d(TAG, "Validating password " + etPassword.getText().toString());
        if(etUsername.getText().toString().isEmpty() || !validator.isInputSanitized(etUsername.getText().toString(), null)) {
            Log.d(TAG, "Invalid username.");
            Toast.makeText(this, R.string.usr_bad_format, Toast.LENGTH_SHORT).show();
            return false;
        }
        else if (etPassword.getText().toString().isEmpty() || !validator.validatePassword(etPassword.getText().toString(), null)){
            Log.d(TAG, "Invalid password. Feedback: " + validator.getPasswordFeedback(etPassword.getText().toString()).toString());
            Toast.makeText(this, R.string.weak_or_bad_format, Toast.LENGTH_SHORT).show();
            return false;
        }
        else {
            Log.d(TAG, "Valid input.");
            return true;
        }
    }

    private void login() {
        Log.d(TAG, "Login");
    }

    @Override
    protected void onStart() {
        super.onStart();
        //If BT is not on, request that it be enabled.
        if (!mBluetoothAdapter.isEnabled()) {
            Intent enableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            startActivityForResult(enableIntent, REQUEST_ENABLE_BT);

        } else if ( mFileCipheringService == null ) {
            setUpService();
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (mFileCipheringService != null) {
            mFileCipheringService.stop();
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        if (mFileCipheringService != null){
            // Only if the state is STATE_NONE, do we know that we haven't yet started
            if(mFileCipheringService.getState() == BluetoothFileCipheringService.STATE_NONE) {
                mFileCipheringService.start();
            }
        }
    }

    /**
     * Makes this device discoverable
     */
    private void ensureDiscoverable() {
        if (mBluetoothAdapter.getScanMode() !=
                BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE) {
            Intent discoverableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
            discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 0); // Always discoverable
            startActivity(discoverableIntent);
            Toast.makeText(this, R.string.warn_set_to_discoverable, Toast.LENGTH_SHORT).show();
        }
    }
    public void onActivityResult (int requestCode, int resultCode, Intent data) {
        switch(requestCode){
            case REQUEST_ENABLE_BT:
                // When the request to enable Bluetooth returns
                if (resultCode == Activity.RESULT_OK) {
                    // Make it discoverable
                    ensureDiscoverable();
                    // BT is now enabled, so set up a chat session
                    setUpService();
                } else {
                    // User did not enable Bluetooth or an error occurred
                    Toast.makeText(this, R.string.bt_not_enabled_leaving, Toast.LENGTH_SHORT).show();
                    this.finish();
                }

        }
    }

    private void setUpService() {
        mFileCipheringService = new BluetoothFileCipheringService();
    }


    /*    private final Handler mHandler = new Handler() {
     @Override
        public void handleMessage(Message msg) {
            switch(msg.what) {
                case Constants.MESSAGE_STATE_CHANGE:
                    switch(msg.arg1) {
                        case BluetoothFileCipheringService.STATE_CONNECTED:
                            //setStatus(get);
                            break;
                        case BluetoothFileCipheringService.STATE_CONNECTING:
                            // set status
                            break;
                        case BluetoothFileCipheringService.STATE_LISTEN:
                        case BluetoothFileCipheringService.STATE_NONE:
                            // setStatus
                            break;
                    }
                    break;
                case Constants.MESSAGE_TO_SERVER:
                    // byte[] writeBuf = (byte[]) obj;
                    Toast.makeText(this, "", Toast.LENGTH_SHORT).show();
            }
        }
    }*/

    
}
