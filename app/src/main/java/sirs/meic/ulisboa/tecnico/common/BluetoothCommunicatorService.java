package sirs.meic.ulisboa.tecnico.common;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;

import javax.crypto.KeyGenerator;

/**
 * Created by Belem on 03/12/2016.
 */

public abstract class BluetoothCommunicatorService implements IService{
    private static final String TAG = "BTCommunicatorService";

    // Connection specific

    private static final String SOCKET_TYPE = "Secure";

    // Unique UUID for this application
    private static final String NAME_SECURE = "BluetoothFileCipheringSecure";
    private static final UUID MY_UUID_SECURE = UUID.randomUUID();

    // Constants that indicate the current connection state
    public static final int STATE_NONE = 0;         // we're doing nothing
    public static final int STATE_LISTEN = 1;       // now listening for incoming connections
    public static final int STATE_CONNECTING = 2;   // now initiating an outgoing connection
    public static final int STATE_CONNECTED = 3;    // now connected to a remote device

    // Connection Specific

    private final BluetoothAdapter mAdapter;

    private AcceptThread mSecureAcceptThread;
    private ConnectThread mConnectThread;
    private ConnectedThread mConnectedThread;
    private int mState;
    private final Handler mHandler;

    public BluetoothCommunicatorService(Handler mHandler) {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mState = STATE_NONE;
        this.mHandler = mHandler;
    }

    /**
     * Set the current state of the connection
     * @param aState An integer defining the current connection state
     */
    private synchronized void setState(int aState) {
        Log.d(TAG, "setState() " + mState + "->" + aState);
        mState = aState;
        mHandler.obtainMessage(Constants.MESSAGE_STATE_CHANGE, aState, -1).sendToTarget();
    }
    /**
     *  Return the current connection state
     */
    public synchronized int getState() {
        return mState;
    }

    /**
     * Start the service. Specifically start AThread to begin a session in listening (server) mode.
     * Called by the Activity onResume().
     */
    @Override
    public synchronized void start() {
        Log.d(TAG, "start");

        // Cancel any thread attempting to make a connection
        if (mConnectThread != null){
            mConnectThread.cancel();
            mConnectThread = null;
        }

        // Cancel any thread currently running a connection
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        setState(STATE_LISTEN);
        // Start the thread to listen
        if (mSecureAcceptThread == null) {
            mSecureAcceptThread = new AcceptThread();
        }
    }

    /**
     * Start the ConnectThread to initiate a connection to a remote device.
     *
     * @param device TheBluetoothDevice to connect
     */
    public synchronized void connect(BluetoothDevice device) {
        Log.d(TAG, "connect to: " + device);

        // Cancel any thread attempting to make a connection
        if (mState == STATE_CONNECTING) {
            if (mConnectThread != null) {
                mConnectThread.cancel();
                mConnectThread = null;
            }
        }
        // Cancel any thread currently running a connection
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        // Start the thread to connect with the given device
        mConnectThread = new ConnectThread(device);
        mConnectThread.start();
        setState(STATE_CONNECTING);
    }

    /**
     *  Start the ConnectedThread to begin managing a Bluetooth connection
     * @param socket The BluetoothSocket on which the connection was made
     * @param device The BluteoothDevice that has been connected
     */
    public synchronized void connected (BluetoothSocket socket, BluetoothDevice device) {
        Log.d(TAG, "Securely connected");
        // Cancel the THread that completed the connection
        if (mConnectThread != null) {
            mConnectThread.cancel();
            mConnectThread = null;
        }

        // Cancel any thread currently running a connection
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }

        // Cancel the accept thread because we only want to connect to one device
        if(mSecureAcceptThread != null) {
            mSecureAcceptThread.cancel();
            mSecureAcceptThread = null;
        }

        // Start the thread to manage the connection and perform transmissions
        mConnectedThread = new ConnectedThread(socket);
        mConnectedThread.start();
        Message msg = mHandler.obtainMessage(Constants.MESSAGE_DEVICE_NAME);
        Bundle bundle = new Bundle();
        bundle.putString(Constants.DEVICE_NAME, device.getName());
        msg.setData(bundle);

        setState(STATE_CONNECTED);
    }

    /**
     * Stop all threads
     */
    @Override
    public synchronized void stop() {
        Log.d(TAG, "stop");
        if (mConnectThread != null) {
            mConnectThread.cancel();
            mConnectThread = null;
        }
        if (mConnectedThread != null) {
            mConnectedThread.cancel();
            mConnectedThread = null;
        }
        if (mSecureAcceptThread == null) {
            mSecureAcceptThread.cancel();
            mSecureAcceptThread = null;
        }
        setState(STATE_NONE);
    }

    /**
     *  Write to ConnectedThread in an unsynchronized manner
     *  @param out The bytes to write
     *  @see ConnectedThread#write(byte[])
     */
    public synchronized void write(byte[] out) {
        // Create temporary object
        ConnectedThread r;
        // Synchronize a copy of the ConnectedThread
        synchronized (this) {
            if (mState != STATE_CONNECTED) return;
            r = mConnectedThread;
        }
        // Perform the write unsychronized
        r.write(out);
    }

    /**
     *  Indicate that the ocnnection attempt failed
     */
    private void connectionFailed() {
        // send a Failure message back to the activity
        Message msg = mHandler.obtainMessage(Constants.MESSAGE_TOAST);
        Bundle bundle = new Bundle();
        bundle.putString(Constants.TOAST, "Unable to connect device");
        msg.setData(bundle);
        mHandler.sendMessage(msg);

        // Start the service over to restart listening mode
        BluetoothCommunicatorService.this.start();
    }
    /**
     * Indicate that the connection was lost
     */
    private void connectionLost() {
        Message msg = mHandler.obtainMessage(Constants.MESSAGE_TOAST);
        Bundle bundle = new Bundle();
        bundle.putString(Constants.TOAST, "Device connection was lost");
        msg.setData(bundle);
        // Start the service over to restart listening mode
        BluetoothCommunicatorService.this.start();
    }

    protected abstract void receive(byte[] aBuffer);


    /**
     * This thread runs while listening for incoming bluetooth connections. It behaves
     * like a server side client. It runs until a connection is accepted (or until cancelled).
     */
    private class AcceptThread extends Thread {
        // The local server socket
        private final BluetoothServerSocket mmServerSocket;
        public AcceptThread(){
            BluetoothServerSocket tmp = null;
            // create a new listening server socket
            try{
                tmp = mAdapter.listenUsingRfcommWithServiceRecord(NAME_SECURE, MY_UUID_SECURE);
            } catch (IOException e) {
                Log.e(TAG, "Socket type: Secure listen() failed", e);
            }
            mmServerSocket = tmp;
        }
        public void run() {
            Log.d(TAG, "Socket type: Secure begin mAcceptThread " + this);

            setName("AcceptThread" + SOCKET_TYPE);
            BluetoothSocket socket = null;
            // listen to the server socket if we're not connected
            while ( mState != STATE_CONNECTED) {
                try {
                    // This is a blocking call and will only return on a
                    // successful connection or an exception
                    socket = mmServerSocket.accept();
                } catch (IOException e) {
                    Log.e(TAG, "Socket type: Secure accept() failed", e);
                    break;
                }

                // if a connection was accepted
                if (socket != null) {
                    synchronized (BluetoothCommunicatorService.this) {
                        switch (mState) {
                            case STATE_LISTEN:
                            case STATE_CONNECTING:
                                // Situation normal. Start the connected thread.
                                connected(socket, socket.getRemoteDevice());
                                break;
                            case STATE_CONNECTED:
                                //either not ready or already connected. Terminate new socket.
                                try {
                                    socket.close();
                                } catch (IOException e) {
                                    Log.e(TAG, "Could not close unwanted socket", e);
                                }
                                break;
                        }
                    }
                }
            }
            Log.i(TAG, "END mAcceptThread, socket type Secure");
        }

        public void cancel() {
            Log.d(TAG, "Socket type Secure: Cancel " + this);
            try {
                mmServerSocket.close();
            } catch (IOException e) { Log.e(TAG, "Close() of server failed", e);
            }
        }
    }

    /**
     * This thread runs while attempting to mak an outgoing connection with a device.
     * It runs straight through; the connection either succeeds or fails.
     */
    private class ConnectThread extends Thread {
        private final BluetoothSocket mmSocket;
        private final BluetoothDevice mmDevice;

        public ConnectThread(BluetoothDevice device) {
            mmDevice = device;
            BluetoothSocket tmp = null;

            // Get a BluetoothSocket for a connection with the
            // given BluetoothDevice
            try {
                tmp = device.createRfcommSocketToServiceRecord(MY_UUID_SECURE);
            } catch (IOException e) {
                Log.e(TAG, "secure socket create() failed", e);
            }
            mmSocket = tmp;
        }

        public void run() {

            Log.d(TAG, "BEGIN mConnectThread Secure socket");
            setName("ConnectThread" + SOCKET_TYPE);

            // Always cancel discovery because it will slow down a connection
            //mAdapter.cancelDiscovery();

            // Make a connection to the BluetoothSocket
            try {
                // This is a blocking call and will only return on a
                // successful connection or an exception
                mmSocket.connect();
            } catch (IOException e) {
                try {
                    mmSocket.close();
                } catch (IOException e1) {
                    Log.e(TAG, "unable to close() secure socket during connection failure", e);
                }
                connectionFailed();
                return;
            }
            // Reset the ConnectThread because we're done
            synchronized (BluetoothCommunicatorService.this) {
                mConnectThread = null;
            }
            // start the connected thread
            connected(mmSocket, mmDevice);
        }

        public void cancel() {
            try {
                mmSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "close of connect to secure socket failed", e);
            }
        }
    }

    /**
     * This thread runs during a connection with a remote device.
     * It handles all incoming and outgoing transmissions.
     */
    private class ConnectedThread extends Thread {
        private final BluetoothSocket mmSocket;
        private final InputStream mmInStream;
        private final OutputStream mmOutputStream;

        public ConnectedThread (BluetoothSocket socket) {
            Log.d(TAG, "Create connectedThread");
            mmSocket = socket;
            InputStream tmpIn = null;
            OutputStream tmpOut = null;

            //Get tbe BluetoothSocket input and output streams
            try {
                tmpIn = socket.getInputStream();
                tmpOut = socket.getOutputStream();
            } catch (IOException e) {
                Log.e(TAG, "temp sockets not created", e);
            }
            mmInStream = tmpIn;
            mmOutputStream = tmpOut;
            if(tmpOut != null)
                init();
        }

        public void run() {
            Log.i(TAG, "BEGIN mConnectedThread");
            byte[] buffer = new byte[1024];
            int bytes;

            // Keep listening to the InputStream while connected
            while (mState == STATE_CONNECTED) {
                try {
                    bytes = mmInStream.read(buffer);

                    mHandler.obtainMessage(Constants.MESSAGE_FROM_SERVER, bytes, -1, buffer).sendToTarget();
                } catch (IOException e) {
                    Log.e(TAG, "===== [disconnected] ======", e);
                    connectionLost();
                    // Start the service over to restart listening mode
                    BluetoothCommunicatorService.this.start(); // TODO - Quero é começar a ligaçao novamente
                    break;
                }
            }
        }

        public void write(byte[] buffer) {
            try {
                mmOutputStream.write(buffer);
            } catch (IOException e) {
                Log.e(TAG, "Exception during write", e);
            }
        }

        public void cancel(){
            try {
                mmSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "close() of connect socket failed", e);
            }
        }
    }

    protected abstract void init();


}
