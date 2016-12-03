package sirs.meic.ulisboa.tecnico.common;

import android.bluetooth.BluetoothAdapter;

import java.security.NoSuchAlgorithmException;

import sirs.meic.ulisboa.tecnico.sirs_proj_client.MainActivity;

/**
 * Created by Belem on 03/12/2016.
 */

public class BluetoothFileCipheringService extends Communicator implements IService {

    // Constants that indicate the current connection state
    public static final int STATE_NONE = 0;         // we're doing nothing
    public static final int STATE_LISTEN = 1;       // now listening for incoming connections
    public static final int STATE_CONNECTING = 2;   // now initiating an outgoing connection
    public static final int STATE_CONNECTED = 3;    // now connected to a remote device

    private final BluetoothAdapter mAdapter;
    private int mState;

    public BluetoothFileCipheringService()   {
        super();
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mState = STATE_NONE;
    }

    @Override
    public void start() {
        // TODO - AUTO GENERATED METHOD
        System.out.println("=========================STARTED====================================");
    }

    @Override
    public void stop() {
        // TODO - AUTO GENERATED METHOD
    }

    /**
     * Set the current state of the connection
     * @param aState An integer defining the current connection state
     */
    private synchronized void setState(int aState) {
        mState = aState;
    }

    /**
     *  Return the current connection state
     */
    public synchronized int getState() {
        return mState;
    }
}
