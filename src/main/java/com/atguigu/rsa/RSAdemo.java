package com.atguigu.rsa;


import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSAdemo
 *
 * @Author: 马伟奇
 * @CreateTime: 2020-05-05
 * @Description:
 */
public class RSAdemo {
    public static void main(String[] args) throws Exception {
        java.lang.String input = "硅谷12";
//        // 创建密钥对
//        // KeyPairGenerator:密钥对生成器对象
        java.lang.String algorithm = "RSA";
//        // 读取私钥
        PrivateKey privateKey = getPrivateKey("a.pri", algorithm);
//        System.out.println(privateKey);
        // 读取公钥key
        PublicKey publicKey = getPublicKey("a.pub", algorithm);
//        System.out.println(publicKey);


//        //生成密钥对并保存在本地文件中
//        generateKeyToFile(algorithm, "a.pub", "a.pri");
//
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
//        // 生成密钥对
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        // 生成私钥
//        PrivateKey privateKey = keyPair.getPrivate();
//        // 生成公钥
//        PublicKey publicKey = keyPair.getPublic();
        // 获取私钥的字节数组
        byte[] privateKeyEncoded = privateKey.getEncoded();
        // 获取公钥字节数组
        byte[] publicKeyEncoded = publicKey.getEncoded();
//        // 使用base64进行编码
        String privateEncodeString = Base64.encode(privateKeyEncoded);
        String publicEncodeString = Base64.encode(publicKeyEncoded);
        // 打印公钥和私钥
//        System.out.println("privateEncodeString\t"+privateEncodeString);
//        System.out.println("publicEncodeString\t"+publicEncodeString);
//
//
//        String s = encryptRSA(algorithm, privateKey, input);
//        System.out.println(s);
//        String s1 = decryptRSA(algorithm, publicKey, s);
//        System.out.println(s1);
        String transformation1 = "RSA/ECB/PKCS1Padding";
        String transformation2 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
        String transformation3 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        // 公钥加密

        String jiami = encryptRSA(transformation1, publicKey, input);
//        String jiami = "wqPDhTPCkH7DjWFww4oJdsOcw7Riw7tVYMO+asOlHi8/I0RbC8KdR33CrcKGwpRMawASw6vDnsKdbcOmw6TCgDRACWfCnMOLQ8KVcsORw654w5TCtsKSwo3CrATCu3k6ZUEKwpHCi8KiwrxrCC3DjcObT8Ouw79bFMKDwrJuS8KzwrJSM8ODwqXCpMOTdMKITTvCn17CscOhwpQGwpnCtFsOTxTClMKcw7XCtEFKw70iI1HCssOnw5nDtEDDscKWw74Awo9pdcK6XsKsQV/DlEPCmC/CnH0eT8Oxw5vCkQQnC0rCuMKLfRccwp1Se8Oww4FAw5HDusOAw4cVw6dGQg3DkCHCnsKPPh0Sw5VmEcKEw7dRwrLDlEdpwqrDoMKOw7ZlewfDpgtyE8Oww67CksONwoUMwp/ClsK4wpHDogpjw7A9ZsOgScKJw4rDuBfDvcKbQcKVwpbCtsKFSMKtBVvDh8OhVU0DwpfDlcO7KsOmMsOoNU3CqSPDhsOjw77Cu8OeLxU=";
        System.out.println(jiami);
        System.out.println(jiami.length());

//        String jiemi = decryptRSA(transformation1, privateKey, jiami);
//        System.out.println(jiemi);

        String jiemi = RSAdemo2.decryptRSA2(jiami, privateEncodeString);
        System.out.println(jiemi);

//        String jiemi = RSAHelper.decipher(jiami, privateEncodeString);
//        System.out.println(jiemi);

    }

    /**
     * 读取公钥
     *
     * @param publicPath 公钥路径
     * @param algorithm  算法
     * @return
     */
    public static PublicKey getPublicKey(String publicPath, String algorithm) throws Exception {
        String publicKeyString = FileUtils.readFileToString(new File(publicPath), Charset.defaultCharset());
        // 创建key的工厂
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        // 创建公钥规则
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(publicKeyString));
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 读取私钥
     *
     * @param priPath   私钥的路径
     * @param algorithm 算法
     * @return 返回私钥的key对象
     */
    public static PrivateKey getPrivateKey(String priPath, String algorithm) throws Exception {
        String privateKeyString = FileUtils.readFileToString(new File(priPath), Charset.defaultCharset());
        // 创建key的工厂
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        // 创建私钥key的规则
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyString));
        // 返回私钥对象
        return keyFactory.generatePrivate(keySpec);
    }


    /**
     * 解密数据
     *
     * @param algorithm  : 算法
     * @param encrypted  : 密文
     * @param privateKey : 密钥
     * @return : 原文
     * @throws Exception
     */
    public static String decryptRSA(String algorithm, Key privateKey, String encrypted) throws Exception {
        // 创建加密对象
        Cipher cipher = Cipher.getInstance(algorithm);
        // 私钥解密
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // 公钥解密
//        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        // 使用base64进行转码
        byte[] decode = Base64.decode(encrypted);


        // 使用私钥进行解密
        byte[] bytes1 = cipher.doFinal(decode);
        return new String(bytes1);
    }


    /**
     * 使用密钥加密数据
     *
     * @param algorithm : 算法
     * @param input     : 原文
     * @param publicKey : 密钥
     * @return : 密文
     * @throws Exception
     */
    public static String encryptRSA(String algorithm, Key publicKey, String input) throws Exception {
        // 创建加密对象
        Cipher cipher = Cipher.getInstance(algorithm);
        // 对加密进行初始化
        // 第一个参数：加密的模式
        // 第二个参数：你想使用公钥加密还是私钥加密
        // 我想使用私钥进行加密
//        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
//        公钥加密
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // 使用私钥进行加密
        byte[] bytes = cipher.doFinal(input.getBytes());
        return Base64.encode(bytes);
    }


    /**
     * 保存公钥和私钥，把公钥和私钥保存到根目录
     *
     * @param algorithm 算法
     * @param pubPath   公钥路径
     * @param priPath   私钥路径
     */
    private static void generateKeyToFile(String algorithm, String pubPath, String priPath) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // 生成私钥
        PrivateKey privateKey = keyPair.getPrivate();
        // 生成公钥
        PublicKey publicKey = keyPair.getPublic();
        // 获取私钥的字节数组
        byte[] privateKeyEncoded = privateKey.getEncoded();
        // 获取公钥字节数组
        byte[] publicKeyEncoded = publicKey.getEncoded();
        // 使用base64进行编码
        String privateEncodeString = Base64.encode(privateKeyEncoded);
        String publicEncodeString = Base64.encode(publicKeyEncoded);
        // 把公钥和私钥保存到根目录
        FileUtils.writeStringToFile(new File(pubPath), publicEncodeString, Charset.forName("UTF-8"));
        FileUtils.writeStringToFile(new File(priPath), privateEncodeString, Charset.forName("UTF-8"));

    }
}