package sirs.meic.ulisboa.tecnico.common;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.os.Bundle;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import javax.crypto.KeyGenerator;

/**
 * Created by Belem on 03/12/2016.
 */

public abstract class CommunicatorService implements IService{

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


    // Others
    final public static String  DEFAULT_TOKEN_FILEPATH ="tokens.txt";
    final public static String  SYM_KEY_ALGORITHM = "AES";
    final public static int     SYM_KEY_SIZE = 256;

    // Connection Specific

    private final BluetoothAdapter mAdapter;

    private AcceptThread mSecureAcceptThread;
    private ConnectThread mConnectThread;
    private ConnectedThread mConnectedThread;
    private int mState;

    // Others
    private CryptographyModule cryptoModule;
    private TokensManager tManager;


    public CommunicatorService() {
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        try {
            mState = STATE_NONE;
            KeyGenerator keyGen = KeyGenerator.getInstance(SYM_KEY_ALGORITHM);
            keyGen.init(SYM_KEY_SIZE);
            Key key = keyGen.generateKey();

            cryptoModule = new CryptographyModule(key);
            tManager = new TokensManager();
        } catch (NoSuchAlgorithmException e) {

            e.printStackTrace();
        }
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

    /**
     * Start the service. Specifically start AThread to begin a session in listening (server) mode.
     * Called by the Activity onResume().
     */
    @Override
    public synchronized void start() {
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
     * Start the ConnectThread to iniatiate a connection to a remote device.
     *
     * @param device TheBluetoothDevice to connect
     */
    public synchronized void connect(BluetoothDevice device) {
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

        setState(STATE_CONNECTED);
    }

    /**
     * Stop all threads
     */
    @Override
    public synchronized void stop() {
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
        // Start the service over to restart listening mode
        CommunicatorService.this.start();
    }
    /**
     * Indicate that the connection was lost
     */
    private void connectionLost() {
        // Start the service over to restart listening mode
        CommunicatorService.this.start();
    }


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
                tmp = mAdapter.listenUsingRfcommWithServiceRecord(NAME_SECURE, MY_UUID_SECURE); // todo - WHY?
            } catch (IOException e) {
                //
            }
            mmServerSocket = tmp;
        }
        public void run() {
            setName("AcceptThread" + SOCKET_TYPE);
            BluetoothSocket socket = null;
            // listen to the server socket if we're not connected
            while ( mState != STATE_CONNECTED) {
                try {
                    // This is a blocking call and will only return on a
                    // successful connection or an exception
                    socket = mmServerSocket.accept();
                } catch (IOException e) {
                    e.printStackTrace();
                    break;
                }

                // if a connection was accepted
                if (socket != null) {
                    synchronized (CommunicatorService.this) {
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
                                    e.printStackTrace();
                                }
                                break;
                        }
                    }
                }
            }
        }
        public void cancel() {
            try {
                mmServerSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
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
                e.printStackTrace();
            }
            mmSocket = tmp;
        }

        public void run() {
            setName("ConnectThread" + SOCKET_TYPE);

            // Always cancel discovery because it will slow down a connection
            // We dont do discovery. It's the server who starts the connection
            // mAdapter.cancelDiscovery();

            // Make a connection to the BluetoothSocket
            try {
                // This is a blocking call and will only return on a
                // successful connection or an exception
                mmSocket.connect();
            } catch (IOException e) {
                try {
                    mmSocket.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                connectionFailed();
                return;
            }
            // Reset the ConnectThread because we're done
            synchronized (CommunicatorService.this) {
                mConnectThread = null;
            }
            // start the connected thread
            connected(mmSocket, mmDevice);
        }

        public void cancel() {
            try {
                mmSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
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
            mmSocket = socket;
            InputStream tmpIn = null;
            OutputStream tmpOut = null;

            //Get tbe BluetoothSocket input and output streams
            try {
                tmpIn = socket.getInputStream();
                tmpOut = socket.getOutputStream();
            } catch (IOException e) {
                e.printStackTrace();
            }
            mmInStream = tmpIn;
            mmOutputStream = tmpOut;
        }

        public void run() {
            byte[] buffer = new byte[1024];
            int bytes;

            // Keep listening to the InputStream while connected
            while (mState == STATE_CONNECTED) {
                try {
                    bytes = mmInStream.read(buffer);
                } catch (IOException e) {
                    e.printStackTrace();
                    connectionLost();
                    // Start the service over to restart listening mode
                    CommunicatorService.this.start();
                    break;
                }
            }
        }

        public void write(byte[] buffer) {
            try {
                mmOutputStream.write(buffer);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void cancel(){
            try {
                mmSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


}
