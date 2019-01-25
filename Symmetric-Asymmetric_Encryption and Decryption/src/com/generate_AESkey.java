package com;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Random;

public class generate_AESkey {


    byte[] keyS = new byte[1000000000];


    static byte[] raw;


    public byte[]  generateAes128Key() {
        try {
            Random r = new Random();
            int num = r.nextInt(999999999);
            String keynumber = String.valueOf(num);
            byte[] knumberbyte = keynumber.getBytes();
            keyS = getRawKey128(knumberbyte);


        } catch (Exception e) {
            System.out.println(e);
        }
        return keyS;
    }


    public static byte[] getRawKey128(byte[] seed) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG");
        sr1.setSeed(seed);
        keyGenerator.init(128, sr1);
        SecretKey skey = keyGenerator.generateKey();
        raw = skey.getEncoded();
        return raw;
    }


}
