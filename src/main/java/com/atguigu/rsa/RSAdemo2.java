package com.atguigu.rsa;


//import com.sun.org.apache.xml.internal.security.utils.Base64;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
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

    public static int encode_part_size = 2048 / 8;

    public static String decryptRSA2(String jiami, String privateBase) throws Exception {
        byte[] privateKeyEncoded = Base64.decodeBase64(privateBase);
        byte[] encodedSource = Base64.decodeBase64(jiami);
        int encodePartLen = encodedSource.length / encode_part_size;
        List<byte[]> decodeListData = new LinkedList();
        String decodeStrResult = null;
        // 私钥解密
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int allDecodeByteLen = 0;
        for (int i = 0; i < encodePartLen; i++) {
            byte[] tempEncodeData = new byte[encode_part_size];
            System.arraycopy(encodedSource, i * encode_part_size, tempEncodeData, 0, encode_part_size);
            byte[] decodePartData = cipher.doFinal(tempEncodeData);
            decodeListData.add(decodePartData);
            allDecodeByteLen = decodePartData.length;
        }
        byte[] decodeResultBytes = new byte[allDecodeByteLen];
        for (int i = 0, curPosition = 0; i < encodePartLen; i++) {

            byte[] tempSourceBytes = decodeListData.get(i);
            int tempSourceBytesLen = tempSourceBytes.length;
            System.arraycopy(tempSourceBytes, 0, decodeResultBytes, curPosition, tempSourceBytesLen);
            curPosition += tempSourceBytesLen;
        }
        decodeStrResult = new String(decodeResultBytes, "UTF-8");

        return decodeStrResult;
    }

}