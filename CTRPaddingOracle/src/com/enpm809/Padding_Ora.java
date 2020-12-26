package com.enpm809;

public class Padding_Ora {
    private CTR ctrMode = null;
    private byte[] ciphertext = null;

    public Padding_Ora(CTR ctrMode, byte[] ciphertext)
    {
        this.ctrMode = ctrMode;
        this.ciphertext = ciphertext;
    }

    public byte[] getChallengeCiphertext(){
        return ciphertext.clone();
    }

    public boolean hasPaddingError(byte[] ciphertext) {
        try {
            ctrMode.decrypt_pad(ciphertext);
            return false;
        }
        catch(Exception e) {
            return true;
        }
    }

}
