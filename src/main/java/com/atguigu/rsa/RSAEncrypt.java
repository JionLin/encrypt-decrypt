package com.atguigu.rsa;

/**
 * @author johnny
 * @Classname RSAEncrypt
 * @Description
 * @Date 2022/5/10 15:12
 */

import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAEncrypt {

    public static final String transformation0 = "RSA";
    public static final String transformation1 = "RSA/ECB/PKCS1Padding";
    public static final String transformation2 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String transformation3 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String transformation4 = "RSA/ECB/OAEPWithMD5AndMGF1Padding";
    private static Map<Integer, String> keyMap = new HashMap<Integer, String>();  //用于封装随机产生的公钥与私钥
    public static void main(String[] args) throws Exception {
        //生成公钥和私钥
        genKeyPair();
        //加密字符串
        String message = "df77382011";
//        System.out.println("随机生成的公钥为:" + keyMap.get(0));
//        System.out.println("随机生成的私钥为:" + keyMap.get(1));
        String gongyao="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+PAirmC71tOy/c+hW+w6r3dXoGjl9wSjwi28T4qBVT5Kmqudmzucdzb47aUm/vlpOd9kthfkg6bOgBIlNFJw2Q0CzGbOeqEC0TqYHnP8bDZ5q/HSstQxnf8jmbHe/MhOw7iVc6mYZ5WUhB5z6S42vLi82SF7lTqY3L25yWtx47wIDAQAB";
        String siyao="MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL48CKuYLvW07L9z6Fb7Dqvd1egaOX3BKPCLbxPioFVPkqaq52bO5x3NvjtpSb++Wk532S2F+SDps6AEiU0UnDZDQLMZs56oQLROpgec/xsNnmr8dKy1DGd/yOZsd78yE7DuJVzqZhnlZSEHnPpLja8uLzZIXuVOpjcvbnJa3HjvAgMBAAECgYEAu6dsxhgw+p+mipVDs8mkB1WlFHgKDkrkn6RrxingD0eXWmFsMrYWtgemh+Sso0CaxJzk10s5HYZrcoYHCsox7H911w75eDC4YlpR6pW0HVR7hQSplAkz4rQG2EYeLU6ZbqFKj4zg2EyuFW0b7volYPSHAGKFy069O+SiKUuM78ECQQD0XDWzolh8cTC/rwQwUuefQunYyjGnHGaiyJP5tNR4z8OW+SLA8I2lAfKdoQvvS4Jtt0IM2bH8Gwv0C/ECcvUrAkEAx0vNPjaAIq9IsA2ElRGgNxr/4yQQGCN3eIIwoHsOBvKmLZrZCRzzweYKOUGLwCA76ywgStQfQGOniLCaUVKxTQJAHR3TpEjm5EUUevKevCdUxAxUEuncyr2+mQzvXOSoIJEZDCc5deXz6sJ1p0SmSGgl7W7VpvRVmeWbIgQ+Pn12KwJBAMAzloj9Pq40pcFECC1LhlweqdGBIhRlf/60b/kVM/33XdR1lgJ37Y1+MTXuxLxRWff/4lTIJiuO8C+fQfRT77ECQCXkqdI3zy5PQu966S4Z1UoECDqFmW7KWjKWLqMw1pF9P7+PlbwI43yGTdHQVwnJxu4FGOZ0bjkUVrakQFdy5CA=";
        String messageEn = encrypt(message,keyMap.get(0));
        //加密后内容
        messageEn ="ecKPw6QvTkE+dcKnwqMbXlPDrMKawrjDgcOowqnDqsO8w4HDp8KpwqjDiHoAwovDgnwsTAjCkgHDsBpOUUnDoMOEVFsdVMOswpYJFcKJw6IYdyEYwo7DrsO7w7UUwokDNcKHT8KPfljDvsOCLRTCocOlAxjDkMOsw43DkcOkbG8uwrs2KsKjCWszw4B6G8OVw5nCjMOawrwiw54Ow6dTBTxnwobCh0/Dj8KLA2tRSsO+wqMZUmBRw43DkQnDuw==";
        System.out.println(message + "\t加密后的字符串为:" + messageEn.length());
//        String messageDe = decrypt(messageEn,keyMap.get(1));
        String messageDe = decrypt(messageEn,siyao);
        System.out.println("还原后的字符串为:" + messageDe);
    }

    /**
     * 随机生成密钥对
     * @throws NoSuchAlgorithmException
     */
    public static void genKeyPair() throws NoSuchAlgorithmException {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为96-1024位
        keyPairGen.initialize(1024,new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        // 得到私钥字符串
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
        // 将公钥和私钥保存到Map
        keyMap.put(0,publicKeyString);  //0表示公钥
        keyMap.put(1,privateKeyString);  //1表示私钥
    }
    /**
     * RSA公钥加密
     *
     * @param str
     *            加密字符串
     * @param publicKey
     *            公钥
     * @return 密文
     * @throws Exception
     *             加密过程中的异常信息
     */
    public static String encrypt( String str, String publicKey ) throws Exception{
        //base64编码的公钥
        byte[] decoded = Base64.decodeBase64(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance(transformation2);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
        return outStr;
    }

    /**
     * RSA私钥解密
     *
     * @param str
     *            加密字符串
     * @param privateKey
     *            私钥
     * @return 铭文
     * @throws Exception
     *             解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) throws Exception{
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
        //base64编码的私钥
        byte[] decoded = Base64.decodeBase64(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance(transformation2);
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte));
        return outStr;
    }

}

