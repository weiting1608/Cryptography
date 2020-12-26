package com.enpm809;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.math.BigInteger;

public class CTR
{
    public static final int AES_KEY_SIZE = 128; // in bits
    public static final int IV_LENGTH = 16; // in bytes
    public static final int BLK_LENGTH = 16; // in bytes

    private byte[] key = null;
    private byte[] iv = null;

    public CTR() throws Exception {
        generateKey();
    }

    public int getBlockLen() {
        return BLK_LENGTH;
    }

    protected void generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        SecureRandom random = new SecureRandom();

        key = keyGenerator.generateKey().getEncoded();
    }

    protected void generateIV() throws Exception {
        SecureRandom random = new SecureRandom();
        iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
    }

    public byte[] pad_encrypt(byte[] plaintext) throws Exception
    {
        int padLen = BLK_LENGTH - (plaintext.length % BLK_LENGTH);
        byte[] pad = new byte[padLen];
        for(int i = 0; i < padLen; i++) {
            pad[i] = (byte)padLen;
        }

        byte[] paddedPlaintext = new byte[plaintext.length + padLen];
        System.arraycopy(plaintext, 0, paddedPlaintext, 0, plaintext.length);
        System.arraycopy(pad, 0, paddedPlaintext, plaintext.length, padLen);

        //System.out.println("Padded plaintext: " + DatatypeConverter.printHexBinary(paddedPlaintext));
        return encrypt(paddedPlaintext);
    }

    public byte[] decrypt_pad(byte[] ciphertext) throws Exception {
        assert (iv != null);
        if (ciphertext.length == 0) return null;

        byte[] decryptedText = decrypt(ciphertext);
        int len = decryptedText.length;
        int pad = decryptedText[len - 1];

        assert(pad > 0 && pad <= BLK_LENGTH);

        for(int i = len - pad; i < len; i++) {
            if(decryptedText[i] != (byte)pad) {
                //System.out.println((byte)decryptedText[i]);
                //System.out.println((byte)pad);
                throw new Exception("Invalid padding");
            }
        }

        byte[] plaintext = new byte[len - pad];
        System.arraycopy(decryptedText, 0, plaintext, 0, plaintext.length);
        return plaintext;
    }

    public byte[] encrypt(byte[] plaintext) throws Exception
    {
        // Generate a new IV
        generateIV();

        return runCtr(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) throws Exception
    {
        return runCtr(ciphertext);
    }

    private byte[] runCtr(byte[] text) throws Exception
    {
        assert(iv != null);

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

        // Perform Encryption/Decryption
        byte[] out = cipher.doFinal(text);

        return out;
    }

}

