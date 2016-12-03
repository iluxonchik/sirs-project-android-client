package sirs.meic.ulisboa.tecnico.sirs_proj_client;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import sirs.meic.ulisboa.tecnico.common.BluetoothFileCipheringService;
import sirs.meic.ulisboa.tecnico.common.StrengthValidator;

public class MainActivity extends AppCompatActivity {

    // Intent Request Codes
    private static final int REQUEST_ENABLE_BT = 1;


    private StrengthValidator validator;

    // Layout views
    private EditText pwEditText;
    private EditText userEditText;
    private Button registerBttn;

    /**
     * Local Bluetooth Adapter
     */

    private BluetoothAdapter mBluetoothAdapter = null;
    private BluetoothFileCipheringService mFileCipheringService = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        registerBttn = (Button) findViewById(R.id.registerBttn);
        pwEditText = (EditText)findViewById(R.id.pwEditText);
        userEditText = (EditText)findViewById(R.id.userEditText);

        validator = new StrengthValidator();

        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        if (mBluetoothAdapter == null) {
            Toast.makeText(this, R.string.bt_not_enabled_leaving, Toast.LENGTH_SHORT).show();
            try {
                Thread.currentThread().sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                this.finish();
            }
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        //If BT is not on, request that it be enabled.
        if (!mBluetoothAdapter.isEnabled()) {
            //Intent enableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            //startActivityForResult(enableIntent, REQUEST_ENABLE_BT);
            ensureDiscoverable();
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
        if(mBluetoothAdapter.getScanMode() !=
                BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE) {
            Intent discoverableIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE);
            discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300);
            startActivity(discoverableIntent);
        }
    }
    public void onActivityResult (int requestCode, int resultCode, Intent data) {
        switch(requestCode){
            case REQUEST_ENABLE_BT:
                // When the request to enable Bluetooth returns
                if (resultCode == Activity.RESULT_OK) {
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

    // TODO - GUI
    public void signUp(View view) {
        String pwPattern = "[a-z][a-z0-9_-\\.]*";
        if(userEditText.getText().toString().isEmpty() || !validator.isInputSanitized(userEditText.getText().toString(), null)) {
            // TODO - Alert the user that the username mustn'
        }
        else if (pwEditText.getText().toString().isEmpty() || !validator.validatePassword(pwEditText.getText().toString(), null)){
            // TODO - Alert the user that the username mustnt
            // TODO - Update a progress bar according to Score to show how weak the password is

        }
        else {

}
    }
}
