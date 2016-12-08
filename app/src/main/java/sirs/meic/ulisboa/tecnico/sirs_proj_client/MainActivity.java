package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Intent;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import sirs.meic.ulisboa.tecnico.common.BluetoothCommunicatorService;
import sirs.meic.ulisboa.tecnico.common.BluetoothFileCipheringService;
import sirs.meic.ulisboa.tecnico.common.Constants;
import sirs.meic.ulisboa.tecnico.common.NeedToLoginException;
import sirs.meic.ulisboa.tecnico.common.StrengthValidator;

import static android.widget.Toast.*;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private static final String ADDRESS = "24:0A:64:91:D4:D0";

    // Intent Request Codes
    private static final int REQUEST_ENABLE_BT = 1;

    private EditText etUsername;
    private EditText etPassword;
    private Button bLogin;
    private StrengthValidator validator;

    private String mConnectedDevice = null;

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
            makeText(this, R.string.bt_not_enabled_leaving, LENGTH_SHORT).show();
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
            makeText(this, R.string.usr_bad_format, LENGTH_SHORT).show();
            return false;
        }
        else if (etPassword.getText().toString().isEmpty() || !validator.validatePassword(etPassword.getText().toString(), null)){
            Log.d(TAG, "Invalid password. Feedback: " + validator.getPasswordFeedback(etPassword.getText().toString()).toString());
            makeText(this, R.string.weak_or_bad_format, LENGTH_SHORT).show();
            return false;
        }
        else {
            Log.d(TAG, "Valid input.");
            return true;
        }
    }

    private void login() {
        Log.d(TAG, "Login");
        try {
            mFileCipheringService.login(etUsername.getText().toString(), etPassword.getText().toString());
            return;
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "No key spec exception", e);
            makeText(this, "Due to unexpected exception we couldn't login.", LENGTH_SHORT).show();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "No key spec exception", e);
            makeText(this, "Due to unexpected exception we couldn't login.", LENGTH_SHORT).show();
        } catch (NeedToLoginException e) {
            makeText(this, "Need to login again.", LENGTH_SHORT).show();
            Log.e(TAG, "No key spec exception", e);
        }
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
            makeText(this, R.string.warn_set_to_discoverable, LENGTH_SHORT).show();
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
                    makeText(this, R.string.bt_not_enabled_leaving, LENGTH_SHORT).show();
                    this.finish();
                }

        }
    }

    private void setUpService() {
        Log.d(TAG, "setUpService()");
        mFileCipheringService = new BluetoothFileCipheringService(mHandler);
        connectDevice(Constants.BT_ADDRESS_SONY_XPERIA);
        /*try {
            mFileCipheringService.login(null, null);
            makeText(this, "No need for login. Already had a token", Toast.LENGTH_SHORT).show();
            bLogin.setEnabled(false);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NeedToLoginException e) {
            e.printStackTrace();
        } */
    }

    public final Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            switch(msg.what) {
                case Constants.MESSAGE_STATE_CHANGE:
                    switch(msg.arg1) {
                        case BluetoothFileCipheringService.STATE_CONNECTED:
                            Toast.makeText(MainActivity.this, "Connected", Toast.LENGTH_SHORT).show();
                            break;
                        case BluetoothCommunicatorService.STATE_CONNECTING:
                            Toast.makeText(MainActivity.this, "Connecting", Toast.LENGTH_SHORT).show();
                            break;
                        case BluetoothCommunicatorService.STATE_LISTEN:
                        case BluetoothCommunicatorService.STATE_NONE:
                            Toast.makeText(MainActivity.this, "Not connected", Toast.LENGTH_SHORT).show();
                            break;
                    }
                    break;
                case Constants.MESSAGE_DEVICE_NAME:
                    Toast.makeText(MainActivity.this, "Connected to " + mConnectedDevice, Toast.LENGTH_SHORT).show();
                    break;
                case Constants.MESSAGE_TOAST:
                    Toast.makeText(MainActivity.this, msg.getData().getString(Constants.TOAST), Toast.LENGTH_SHORT).show();
            };
        }
    };

    private void connectDevice(String aDeviceAddress) {
        if(mBluetoothAdapter.checkBluetoothAddress(aDeviceAddress)) {
            mConnectedDevice = aDeviceAddress;
            BluetoothDevice device = mBluetoothAdapter.getRemoteDevice(aDeviceAddress);
            Log.d(TAG, "connectDevice() " + aDeviceAddress + ". Connecting");
            mFileCipheringService.connect(device);
            Log.d(TAG, "connectDevice() " + aDeviceAddress + ".Already connected");
        }
        else {
            Toast.makeText(this, "setUpService() BT_ADDR: " + aDeviceAddress + " not valid", Toast.LENGTH_SHORT).show();
        }

    }


}
