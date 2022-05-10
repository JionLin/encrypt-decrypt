package com.atguigu.rsa;


//import com.sun.org.apache.xml.internal.security.utils.Base64;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.LinkedList;
import java.util.List;

/**
 * RSAdemo
 *
 * @Author: 马伟奇
 * @CreateTime: 2020-05-05
 * @Description:
 */
public class RSAdemo2 {

    public static int encode_part_size = 2048 / 8-11;


    public static final String transformation0 = "RSA";
    public static final String transformation1 = "RSA/ECB/PKCS1Padding";
    public static final String transformation2 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String transformation3 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String transformation4 = "RSA/ECB/OAEPWithMD5AndMGF1Padding";

    public static String decryptRSA2(String jiami, String privateBase)  {
        byte[] privateKeyEncoded = Base64.decodeBase64(privateBase);
        byte[] encodedSource = Base64.decodeBase64(jiami);
        int encodePartLen = encodedSource.length / encode_part_size;
        List<byte[]> decodeListData = new LinkedList();
        String decodeStrResult = null;
        // 私钥解密
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(transformation4);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int allDecodeByteLen = 0;
            for (int i = 0; i < encodePartLen; i++) {
                byte[] tempEncodeData = new byte[encode_part_size];
                System.arraycopy(encodedSource, i * encode_part_size, tempEncodeData, 0, encode_part_size);
                byte[] decodePartData = cipher.doFinal(tempEncodeData);
                decodeListData.add(decodePartData);
                allDecodeByteLen += decodePartData.length;
            }


            byte[] decodeResultBytes = new byte[allDecodeByteLen];
            for (int i = 0, curPosition = 0; i < encodePartLen; i++) {

                byte[] tempSourceBytes = decodeListData.get(i);
                int tempSourceBytesLen = tempSourceBytes.length;
                System.arraycopy(tempSourceBytes, 0, decodeResultBytes, curPosition, tempSourceBytesLen);
                curPosition += tempSourceBytesLen;
            }
            decodeStrResult = new String(decodeResultBytes, "UTF-8");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }catch (Exception e){

        }
        System.out.println("decodeStrResult:\t"+decodeStrResult);
        return decodeStrResult;
    }



    //私钥解密
    public static String decrypt(String cryptograph,Key privatekey) throws Exception{ //cryptograph-通过rsa公钥加密得到的参数  privatekey-与公钥对应的私钥
        /** 将文件中的私钥对象读出 */
        // cryptograph= new String(cryptograph.getBytes(),"gbk");

//        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(""));
//        Key key = (Key) ois.readObject();
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
//        Cipher cipher = Cipher.getInstance("RSA");
        Cipher cipher = Cipher.getInstance(transformation0);
//        cipher.init(Cipher.DECRYPT_MODE, key);
        cipher.init(Cipher.DECRYPT_MODE, privatekey);
        BASE64Decoder decoder = new BASE64Decoder();
        byte[] b1 = decoder.decodeBuffer(cryptograph);
        /** 执行解密操作 */
        byte[] b = null;

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b1.length; i += 512) {
            byte[] subarray = ArrayUtils.subarray(b1, i, i + 512);
            byte[] doFinal = cipher.doFinal(subarray);
            sb.append(new String(doFinal,"utf-8"));
        }
        return sb.toString();

    }


}