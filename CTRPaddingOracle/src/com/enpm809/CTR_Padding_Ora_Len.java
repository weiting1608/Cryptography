package com.enpm809;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.util.Scanner;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.math.BigInteger;

public class CTR_Padding_Ora_Len
{
    private Padding_Ora oracle = null;
    public CTR_Padding_Ora_Len(Padding_Ora oracle)
    {
        this.oracle = oracle;
    }
    int i_out;

    public int getPlaintextLen()
    {
        byte[] ciphertext = oracle.getChallengeCiphertext();
        System.out.println("Challenge ciphertext: ");
        System.out.println(DatatypeConverter.printHexBinary(ciphertext));

        //int blkLen = oracle.getBlockLen();
        int i = 0; //ciphertext.length-blkLen
        while(true) {
            byte c = ciphertext[i];
            ciphertext[i] = 0x00;
            boolean error = oracle.hasPaddingError(ciphertext);
            System.out.print("padding error = " + error + " ");
            System.out.println(DatatypeConverter.printHexBinary(ciphertext));
            ciphertext[i] = c;

            if(!error) {
                i++;
                continue;
            }
            break;
        }
        this.i_out = i;
        return i;
    }
}

