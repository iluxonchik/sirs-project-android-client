package sirs.meic.ulisboa.tecnico.common;

import com.google.common.primitives.Bytes;

import java.io.IOException;

/**
 * Created by Belem on 06/12/2016.
 */

public class FreshnessEnforcer extends FilesManager {
        private String nonceFilePath = "nonces.txt";

        public FreshnessEnforcer() {
            // TODO clean file
        }

        public byte[] getLastSeenNonce() {
        return getLastSeenArg();
    }
        public boolean isRepeated(byte[] aNonce) throws IOException {
            // This should be optimized
            byte[] allNonces = load(nonceFilePath);
            return (Bytes.indexOf(aNonce, allNonces) != -1);
        }
}
