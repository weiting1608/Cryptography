package com.enpm809;

import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;
import com.sun.xml.internal.ws.api.model.wsdl.WSDLOutput;
import org.w3c.dom.ls.LSOutput;
import sun.security.x509.IPAddressName;

import javax.xml.bind.DatatypeConverter;
import java.security.GeneralSecurityException;

public class Padding_Ora_Attack {
    private Padding_Ora oracle = null;
    private CTR_Padding_Ora_Len pt_len = null;
    private CTR ctrMode = null;
    private byte[] ciphertext = null;

    public Padding_Ora_Attack(CTR ctrMode, byte[] ciphertext, Padding_Ora oracle, CTR_Padding_Ora_Len pt_len){
        this.ctrMode = ctrMode;
        this.ciphertext = ciphertext;
        this.oracle = oracle;
        this.pt_len = pt_len;
    }

    byte[] init_plaintext = new byte[16];
    byte[] curr_plaintext = new byte[16];

    public byte[] iniPlaintext() throws Exception {
        int padLen = 16-pt_len.i_out;
//        System.out.println(padLen);
        for(int k = 0; k < pt_len.i_out; k++){
            init_plaintext[k] = 0x00;
        }
        for(int j = pt_len.i_out; j < 16; j++){
            init_plaintext[j] = (byte)(padLen);
        }
        return init_plaintext;
    }

    public byte[] decipherPlain() throws Exception {
        curr_plaintext = init_plaintext;
        byte [] init_ciphertext = oracle.getChallengeCiphertext();
        byte [] curr_ciphertext = init_ciphertext;
        for(int i = pt_len.i_out-1; i >= 0; i--){

            int padLen = 16-i-1;

            for (int k = i+1; k < 16; k++){
                curr_ciphertext[k] = (byte) (curr_ciphertext[k] ^ ((byte)padLen) ^ ((byte)(padLen+1)));
//                System.out.println(DatatypeConverter.printHexBinary(curr_ciphertext));
            }
            byte ci = curr_ciphertext[i];
//            System.out.println(Integer.toHexString(ci));
            for(int j = 0; j < 256; j++){
                curr_ciphertext[i] = (byte) j;
//                System.out.println(DatatypeConverter.printHexBinary(curr_ciphertext));
                boolean error = oracle.hasPaddingError(curr_ciphertext);
                if (error) {
                    continue;
                }
                else {
//                    System.out.println(error);
//                    System.out.println(Integer.toHexString((byte)j));
                    byte ks = (byte) ((byte) j ^ (byte) (padLen+1));
//                    System.out.println(Integer.toHexString(ks));
                    byte pl = (byte) (ks ^ ci);
                    curr_plaintext[i] = pl;
//                    System.out.println(DatatypeConverter.printHexBinary(curr_ciphertext));
//                    System.out.println(DatatypeConverter.printHexBinary(curr_plaintext));
                    break;
                }
            }
            System.out.println("Learned length of plain text: " + (padLen+1));
            System.out.println("Current plaintext: " + DatatypeConverter.printHexBinary(curr_plaintext));
            System.out.println("Current ciphertext: " + DatatypeConverter.printHexBinary(curr_ciphertext));
        }
        byte[] plaintext = new byte[pt_len.i_out];
        System.arraycopy(curr_plaintext,0, plaintext,0, pt_len.i_out);
        System.out.println("------------------------------------------------------");
        return plaintext;
    }

}
