package com.atguigu.rsa;


import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * RSAdemo
 *
 * @Author: 马伟奇
 * @CreateTime: 2020-05-05
 * @Description:
 */
public class RSAdemo3 {

    public static int encode_part_size = 2048 / 8;


    public static final String transformation0 = "RSA";
    public static final String transformation1 = "RSA/ECB/PKCS1Padding";
    public static final String transformation2 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String transformation3 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String transformation4 = "RSA/ECB/OAEPWithMD5AndMGF1Padding";




    public static String decrypt3(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation4);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // it was 344 here
        System.out.println(data.length);

//        byte[] decoded = Base64.getEncoder().encode(data);
//        System.out.println(decoded.length);
        byte[] todecrypt = cipher.doFinal(data);
        // it become 256

        String finalstring = new String(todecrypt, "UTF-8");
        return finalstring;
    }

    public static String decrypt1(String jiami, PrivateKey privateKey) {
        byte[] decode = Base64.getDecoder().decode(jiami);
        System.out.println(decode.length);
//        byte[] encode = Base64.getEncoder().encode(decode);
//        System.out.println(encode.length);
        try {
            String value = decrypt3(decode, privateKey);
            return value;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
}