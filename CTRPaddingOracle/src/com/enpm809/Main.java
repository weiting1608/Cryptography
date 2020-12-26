package com.enpm809;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import sun.awt.geom.AreaOp;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    public static void main(String args[]) throws Exception {
        CTR ctr = new CTR();

        byte[] plaintext = "Cheers".getBytes();
        byte[] challengeText = ctr.pad_encrypt(plaintext);

        Padding_Ora ora = new Padding_Ora(ctr, challengeText);
        CTR_Padding_Ora_Len pt_len = new CTR_Padding_Ora_Len(ora);
        Padding_Ora_Attack decipher = new Padding_Ora_Attack(ctr,challengeText, ora, pt_len);

        System.out.println("Get the paddding oracle (Valid/Invalid padding).");
        System.out.println("First step is to find the length of the plaintext.");
        System.out.println("I think the length of plaintext is: " + pt_len.getPlaintextLen());

        System.out.println("-------------------------------------------------------");
        System.out.println("Hooray! Then decipher the plaintext.");
        decipher.iniPlaintext();
        System.out.println("Plaintext: " + new String(decipher.decipherPlain(), "ASCII"));
    }
}
