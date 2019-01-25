package com;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


public class Server {

    private static final String initVector = "encryptionIntVec";
    public static String stringServerPublicKey;
    public static String stringServerPrivateKey;

    public static void main(String[] args) throws Exception {
        IvParameterSpec ivi = new IvParameterSpec(initVector.getBytes("UTF-8"));

        Map<String, Object> serverKeys = getRSAKeys(); // server keys
        PrivateKey privateKeyServer = (PrivateKey)serverKeys.get("private");
        PublicKey publicKeyServer = (PublicKey)serverKeys.get("public");

        // We access client 0 and client 1 public keys from these classes.
        Client_0 client_0 = new Client_0();
        Map<String,Object> client_0_Keys = client_0.getRSAKeys();
        Client_1 client_1 = new Client_1();
        Map<String,Object> client_1_Keys = client_1.gettRSAKeys();

        PublicKey publicKeyClient_0 = (PublicKey) client_0_Keys.get("public");
        PublicKey publicKeyClient_1 = (PublicKey)client_1_Keys.get("public");



        System.out.println("-----------------------------------");
        byte[] ecryptedClient_0_Publicbyte = encryptPublicKeys(publicKeyClient_0,privateKeyServer);
        String ecryptedClient_0Public = Base64.getEncoder().encodeToString(ecryptedClient_0_Publicbyte);

        System.out.println("Client_0 encrypted Public Key --> " + ecryptedClient_0Public);

        byte[] ecryptedClient_1_Publicbyte =encryptPublicKeys(publicKeyClient_1,privateKeyServer);
        String ecryptedClient_1Public = Base64.getEncoder().encodeToString(ecryptedClient_1_Publicbyte);

        // Şifreli public keyleri çözme
        System.out.println("Client_1 encrypted Public Key --> " + ecryptedClient_1Public);
        System.out.println("-----------------------------------");
        System.out.println("Client 0 certificated  public key --> " +
                Base64.getEncoder().encodeToString(client_0.decryptPublicKeys(publicKeyServer,ecryptedClient_0_Publicbyte)));
        System.out.println("Client 1 certificated  public key  --> " +
                Base64.getEncoder().encodeToString(client_1.decryptPublicKeys(publicKeyServer,ecryptedClient_1_Publicbyte)));


        // AEs key generate and encrypt Image with this key in client 0.
        generate_AESkey key = new generate_AESkey();
        byte[] AesKey = key.generateAes128Key();
        String aeskeyStr = Base64.getEncoder().encodeToString(AesKey);
        System.out.println("-----------------------------------");
        System.out.println("AES key in Client 0 --> " + aeskeyStr);
        byte[] imageByte = client_0.readImagetoByte();
        String imageStr = Base64.getEncoder().encodeToString(imageByte);
        System.out.println("Original image --> " + imageStr);


        // Encrypte image with AES algorithm.
        byte[] encryptedImage = client_0.encryptImage(imageByte,AesKey,ivi);
        String strencryptedImage = Base64.getEncoder().encodeToString(encryptedImage);
        System.out.println("-----------------------------------");
        System.out.println("Encrypted image in Client_0 --> " + strencryptedImage);


        // image hash
        String hashImage = client_0.imageHash();
        System.out.println("Hash(Image) --> " + hashImage );
        byte[] hashImagebyte = Base64.getDecoder().decode(hashImage);
        byte [] digitalSignImage = client_0.encryptImageWithHerPrivateKey(hashImagebyte);
        String digitalSignImageStr = Base64.getEncoder().encodeToString(digitalSignImage);
        System.out.println("-----------------------------------");
        System.out.println("Digital sign hash image with client 0 private key --> " + digitalSignImageStr);


        // Encrypted AES key with Client 1 publickey
        byte [] encryptedAESkey = client_0.encryptAESkey(publicKeyClient_1,AesKey);
        String encryptedAESkeyStr = Base64.getEncoder().encodeToString(encryptedAESkey);
        System.out.println("-----------------------------------");
        System.out.println("Encrypted AES key with Client 1 publickey --> " + encryptedAESkeyStr);


      // decrypted AES key with Client 1 private key
        byte[] decryptedAESkey = client_1.decryptAESKey(encryptedAESkey);
        String decryptedAESkeyStr = Base64.getEncoder().encodeToString(decryptedAESkey);
        System.out.println("-----------------------------------");
        System.out.println("Decrypted AES key with Client 1 private key --> " + decryptedAESkeyStr);



       // decrypted image with AES algorithm in Client 1 .
        byte [] decryptedIamge = client_1.decryptImage(encryptedImage,decryptedAESkey,ivi);
        String decryptedIamgeStr = Base64.getEncoder().encodeToString(decryptedIamge);
        System.out.println("-----------------------------------");
        System.out.println("Decrypted image in Client 1 --> " + decryptedIamgeStr);


        // Saving decrypted image in your file.
        client_1.saveImage(decryptedIamge);



        String receivedImageHash = client_1.imageHashIntegrity();
        System.out.println("Hash(receivedImage) in Client 1 --> " + receivedImageHash);


        byte[] decryptedImageHash = client_1.decrypteImageWithPublickey(digitalSignImage,publicKeyClient_0);
        String decryptedImageHashbyte = Base64.getEncoder().encodeToString(decryptedImageHash);
        System.out.println("Authentication of the image by verifying the digital signature --> " + decryptedImageHashbyte);


    }


    public static Map<String, Object> getRSAKeys() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(1024);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();

        PublicKey publicKey = keyPair.getPublic();

        Base64.Encoder enc = Base64.getEncoder();

        stringServerPublicKey = enc.encodeToString(publicKey.getEncoded());
        stringServerPrivateKey = enc.encodeToString(privateKey.getEncoded());
        System.out.println("-----------------------------------");
        System.out.println("Server Private Key : " + stringServerPrivateKey);
        System.out.println();
        System.out.println("Server Public Key : " + stringServerPublicKey);
        System.out.println(" ");

        Map<String, Object> keys = new HashMap<String, Object>();


        keys.put("private", privateKey);

        keys.put("public", publicKey);

        return keys;

    }

    private static byte[] encryptPublicKeys(PublicKey publicKey, PrivateKey privateKey) throws Exception {


        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE, privateKey);


        return cipher.doFinal(publicKey.getEncoded());
      //  return Base64.getEncoder().encodeToString(cipher.doFinal(publicKey.getEncoded()));

    }


}
