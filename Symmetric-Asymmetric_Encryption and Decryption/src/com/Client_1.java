package com;

import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Client_1 {

    public  String stringClient1PublicKey;
    private   String stringClient1PrivateKey;
    private PrivateKey privateKey;


    public Map<String, Object> gettRSAKeys() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(512);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        privateKey = keyPair.getPrivate();

        PublicKey publicKey = keyPair.getPublic();

        Base64.Encoder enc = Base64.getEncoder();

        stringClient1PublicKey = enc.encodeToString(publicKey.getEncoded());
        stringClient1PrivateKey = enc.encodeToString(privateKey.getEncoded());
        System.out.println("-----------------------------------");
        System.out.println("Client 1 Private Key --> " + stringClient1PrivateKey);
        System.out.println();
        System.out.println("Client 1 Public Key --> " + stringClient1PublicKey);
        System.out.println(" ");

        Map<String, Object> keys = new HashMap<String, Object>();


        keys.put("private", privateKey);

        keys.put("public", publicKey);

        return keys;

    }
    public byte[] decryptPublicKeys(PublicKey publicKey, byte[] encryptedPublic ) throws Exception {


        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE,publicKey);



        return cipher.doFinal(encryptedPublic);

    }

     // Decrypted AES key with client 1 private key
    public byte[] decryptAESKey(byte[] encryptedAES) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

         return cipher.doFinal(encryptedAES);

        //return Base64.getEncoder().encodeToString(cipher.doFinal(encryptedAES));

    }

    // Decrypting, encrypted image with AES algorithm in CBC mode
    public  byte[] decryptImage(byte[] encryptedImag , byte[] AESanahtari, IvParameterSpec iviSpec )
            throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKeySpec secretKeySpec3 = new SecretKeySpec(AESanahtari,0,AESanahtari.length,"AES");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec3,iviSpec);
        byte[] decriptedImages = cipher.doFinal(encryptedImag);
        return decriptedImages;
    }

    // Save image that decrypted in Client 1 class with AES algorithm .
    public  void saveImage(byte[] bytes) throws IOException {

        FileOutputStream fos = new FileOutputStream("decryptedImage.jpg");
        fos.write(bytes);
        System.out.println("Your image saved securely !!");
        fos.close();

    }

    public  String imageHashIntegrity() throws IOException, NoSuchAlgorithmException {

        File fileName = new File("decryptedImage.jpg");
        byte[] buffer = new byte[8192];
        int count;

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
        while ((count = bis.read(buffer)) > 0) {
            digest.update(buffer, 0, count);
        }
        try {
            bis.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] hash = digest.digest();

        return new BASE64Encoder().encode(hash);
    }

    public  byte[] decrypteImageWithPublickey(byte[] sifreliHashresim, PublicKey publicKey ) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,publicKey);

        return cipher.doFinal(sifreliHashresim);


    }

}
