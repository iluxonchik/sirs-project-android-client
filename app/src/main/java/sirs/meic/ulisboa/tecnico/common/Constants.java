package sirs.meic.ulisboa.tecnico.common;

/**
 * Created by Belem on 06/12/2016.
 */

public interface Constants {
    // Message types sent from the BluetoothChatService Handler
    public static final int MESSAGE_STATE_CHANGE = 1;
    public static final int MESSAGE_FROM_SERVER = 2;
    public static final int MESSAGE_TO_SERVER = 3;
    public static final int MESSAGE_DEVICE_NAME = 4;
    public static final int MESSAGE_TOAST = 5;

    public static final String DEVICE_NAME = "device_name";
    public static final String TOAST = "toast";

    public static final String BT_ADDRESS_ZTE_A75 = "4C:CB:F5:BA:AE:22";
    public static final String BT_ADDRESS_SONY_XPERIA = "20:54:76:BB:8E:FD";
    public static final String BT_ADDRESS_TO_CONNECT_TO = "24:0A:64:91:D4:D0";;
}
