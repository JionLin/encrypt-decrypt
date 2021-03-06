package com.atguigu.rsa;

/**
 * @author johnny
 * @Classname RSAHelper
 * @Description
 * @Date 2022/5/10 11:38
 */

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.springframework.util.Base64Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAHelper {

    public static final String transformation0 = "RSA";
    public static final String transformation1 = "RSA/ECB/PKCS1Padding";
    public static final String transformation2 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String transformation3 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String transformation4 = "RSA/ECB/OAEPWithMD5AndMGF1Padding";



    public static final String PUBLIC_KEY_VALUES = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0bb7yxuvRIWOUxlTbTXE\n" +
            "cKX5f4Q6+BBOf1fYJKic9l6Wf1QPmyt6ML7PywaPH861D7eYoQl0bGNK2fKsgcAG\n" +
            "ZzObG5CpmP8ESnSzqcjltdAgx+neCZQy7yUmXUIhpBEQMN80CNYoasOxeZTdPh2w\n" +
            "zhlmwa27ubkvpINtKUfZbg8sQ5wiDGbLM32ej8z2Rl8DNY4vrusJaNXB7LWaRQm7\n" +
            "4lPhLN2B/hMv/Ktif4iNxUCYDY97Xws2kVVu7ffWkn4rnhiCrTw2XMZRjIJq3a4o\n" +
            "4zGWUhYm0usVOLz+yG22cLSCIDhM8tBXL2f3960l4OIQbSObfQkGnqlmi0Fe686p\n" +
            "gwIDAQAB";
    public static final String PRIVATE_KEY_VALUES = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRtvvLG69EhY5T\n" +
            "GVNtNcRwpfl/hDr4EE5/V9gkqJz2XpZ/VA+bK3owvs/LBo8fzrUPt5ihCXRsY0rZ\n" +
            "8qyBwAZnM5sbkKmY/wRKdLOpyOW10CDH6d4JlDLvJSZdQiGkERAw3zQI1ihqw7F5\n" +
            "lN0+HbDOGWbBrbu5uS+kg20pR9luDyxDnCIMZsszfZ6PzPZGXwM1ji+u6wlo1cHs\n" +
            "tZpFCbviU+Es3YH+Ey/8q2J/iI3FQJgNj3tfCzaRVW7t99aSfiueGIKtPDZcxlGM\n" +
            "gmrdrijjMZZSFibS6xU4vP7IbbZwtIIgOEzy0FcvZ/f3rSXg4hBtI5t9CQaeqWaL\n" +
            "QV7rzqmDAgMBAAECggEBAIpVZ5Y8tso+RvmttQhO9TtRYFirArLrHryFV4Am8RLa\n" +
            "pe9rpbe3YCyTUUIdG3/hvDGX68geEnwEqzVFDGGyJwcgVWpDbHwNi+kJPhH7APuD\n" +
            "RHxaWip7ZXW2Ta4ql0JANyvlr888ZQC4AXOvrJjywNPSkaOkVDZYX4LnZrRaPqSH\n" +
            "j9iVGuKK4nbqbXP1tuLyto6bsn3L2KuwrBthtiDPaZ1cRm3aSu/XND030iSGloW/\n" +
            "/f6vHI3U//cPFPdi8p54nbpGTB0E66D2xbfK5+z9dZYoFDZUdMsloR1JgS4vQErr\n" +
            "17165RS7cpWx2HejiKat6qmNFXkHbREpcLDT+lq91LECgYEA7wqm+mIFIYyXEARc\n" +
            "lKKabCKaufKE+7kyBGpAEyon1lYZHw62dCYkGmuXULam4IAz7TesWsbG5SEgDx/A\n" +
            "jeFSoC6NTyyTzSh1I08UHdOJ4xhAa67GnlJG7WLNZFK+itl7v3VOOlGsAYAxaG5q\n" +
            "kQKQ1mKk6C6oGRpQ0aqKxVhoDc0CgYEA4Je2flPUYs33qy4m09UBFx6Xf91/5LvL\n" +
            "iTtEo+HGcMzxmfeV3sawUwtjHhyippN5lTR80JLbYoEvoUMyKt+N5Jnic206alSH\n" +
            "hujsQnO4LCRHz/XwkHnB8Ncd3J67Uaq9PUPY630NIA/ChBAQchsqntJSdVn65PZf\n" +
            "mw7+hO2WxI8CgYB4eX/qlVhMrlS8R9Z5OvJlKZOdv/LyA0aIHxyoDAkD52TF2F5w\n" +
            "b4CmqC8dCNFWOIbzOanuHlzDwkwsEy6y0ysXfB7QFoFvVsKixwo2dhT6lZByNSX5\n" +
            "STJiFfe6ZlGOHUpXFkIU9nCgWQGNxoiDCS4CPrkqI8mozTCKW0+RYpseyQKBgQCR\n" +
            "cK21UQQQl+Dy8YgjVaTHHABvxTi1HwfHbqIcnnCrS4yJcFOVWIWGwbEGJvUNeiMa\n" +
            "BEtvpip7t7zoaWNrcCmrCBwlM27IvMSnEN8uiVGTBEuc2F9YsABvvl6QKBqV4EN8\n" +
            "ERvAI9MEGDCW5PBBdGY9Q2YyqHpZG1L+Ts9ztYgU8QKBgB7bP9eNMrDzgZ6i9pFP\n" +
            "djlcJ+NE0veOLwTA1eQhiIZFSJTI5eyiePTYNIS3GwIyGauzePw5LeBb6rLVBt4Y\n" +
            "NAOgJDeHbPV2bnstONjE7FyUswJivIVD3n3UaVGgBTe6xc468Ws4rmeKZ8/Ph1Nq\n" +
            "ylaViyPWz486JAibF3Kudl5B";
    /**
     * RSA?????????????????????64???????????????512~65536??????????????????1024
     */
//    public static final int KEY_SIZE = 2048;
    public static final int KEY_SIZE = 1024;

    /**
     * ????????????????????????(keysize=1024)
     */
    public static RSAHelper.KeyPairInfo getKeyPair() {
        return getKeyPair(KEY_SIZE);
    }

    /**
     * ????????????????????????
     *
     * @param keySize
     * @return
     */
    public static RSAHelper.KeyPairInfo getKeyPair(int keySize) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(keySize);
            // ?????????????????????????????????keyPair???
            KeyPair keyPair = keyPairGen.generateKeyPair();
            // ????????????
            RSAPrivateKey oraprivateKey = (RSAPrivateKey) keyPair.getPrivate();
            // ????????????
            RSAPublicKey orapublicKey = (RSAPublicKey) keyPair.getPublic();

            RSAHelper.KeyPairInfo pairInfo = new RSAHelper.KeyPairInfo(keySize);
            //??????
            byte[] publicKeybyte = orapublicKey.getEncoded();
            String publicKeyString = Base64.encode(publicKeybyte);
            pairInfo.setPublicKey(publicKeyString);
            //??????
            byte[] privateKeybyte = oraprivateKey.getEncoded();
            String privateKeyString = Base64.encode(privateKeybyte);
            pairInfo.setPrivateKey(privateKeyString);

            return pairInfo;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ??????????????????
     *
     * @param publicKeyBase64
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public static PublicKey getPublicKey(String publicKeyBase64)
            throws InvalidKeySpecException, NoSuchAlgorithmException, Base64DecodingException {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicpkcs8KeySpec =
                new X509EncodedKeySpec(Base64.decode(publicKeyBase64));
        PublicKey publicKey = keyFactory.generatePublic(publicpkcs8KeySpec);
        return publicKey;
    }

    /**
     * ??????????????????
     *
     * @param privateKeyBase64
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String privateKeyBase64)
            throws NoSuchAlgorithmException, InvalidKeySpecException, Base64DecodingException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privatekcs8KeySpec =
                new PKCS8EncodedKeySpec(Base64.decode(privateKeyBase64));
        PrivateKey privateKey = keyFactory.generatePrivate(privatekcs8KeySpec);
        return privateKey;
    }

    /**
     * ??????????????????
     *
     * @param content         ???????????????
     * @param publicKeyBase64 ?????? base64 ??????
     * @return ?????? base64 ?????????????????????
     */
    public static String encipher(String content, String publicKeyBase64) {
        return encipher(content, publicKeyBase64, KEY_SIZE / 8 - 11);
    }

    /**
     * ???????????????????????????????????????
     *
     * @param content         ???????????????
     * @param publicKeyBase64 ?????? base64 ??????
     * @param segmentSize     ????????????,???????????? keySize/8??????????????????0?????????????????????????????????
     * @return ?????? base64 ?????????????????????
     */
    public static String encipher(String content, String publicKeyBase64, int segmentSize) {
        try {
            PublicKey publicKey = getPublicKey(publicKeyBase64);
            return encipher(content, publicKey, segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ????????????
     *
     * @param ciphertext  ??????
     * @param key         ????????????
     * @param segmentSize ???????????????<=0 ?????????
     * @return
     */
    public static String encipher(String ciphertext, java.security.Key key, int segmentSize) {
        try {
            // ???????????????
            byte[] srcBytes = ciphertext.getBytes();

            // Cipher??????????????????????????????????????????RSA
//            Cipher cipher = Cipher.getInstance("RSA");
            Cipher cipher = Cipher.getInstance(transformation1);

            // ??????????????????Cipher?????????????????????
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] resultBytes = null;

            if (segmentSize > 0){
                resultBytes = cipherDoFinal(cipher, srcBytes, segmentSize);} //????????????
            else{
                resultBytes = cipher.doFinal(srcBytes);}
            String base64Str = Base64Utils.encodeToString(resultBytes);
            return base64Str;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ????????????
     *
     * @param cipher
     * @param srcBytes
     * @param segmentSize
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public static byte[] cipherDoFinal(Cipher cipher, byte[] srcBytes, int segmentSize)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        if (segmentSize <= 0){
            throw new RuntimeException("????????????????????????0");}
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int inputLen = srcBytes.length;
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // ?????????????????????
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > segmentSize) {
                cache = cipher.doFinal(srcBytes, offSet, segmentSize);
            } else {
                cache = cipher.doFinal(srcBytes, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * segmentSize;
        }
        byte[] data = out.toByteArray();
        out.close();
        return data;
    }

    /**
     * ??????????????????
     *
     * @param contentBase64    ???????????????,base64 ??????
     * @param privateKeyBase64 ?????? base64 ??????
     * @return
     * @segmentSize ????????????
     */
    public static String decipher(String contentBase64, String privateKeyBase64) {
        return decipher(contentBase64, privateKeyBase64, KEY_SIZE / 8);
    }

    /**
     * ????????????????????????????????????
     *
     * @param contentBase64    ???????????????,base64 ??????
     * @param privateKeyBase64 ?????? base64 ??????
     * @return
     * @segmentSize ????????????
     */
    public static String decipher(String contentBase64, String privateKeyBase64, int segmentSize) {
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyBase64);
            return decipher(contentBase64, privateKey, segmentSize);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ????????????
     *
     * @param contentBase64 ??????
     * @param key           ????????????
     * @param segmentSize   ???????????????????????????0????????????
     * @return
     */
    public static String decipher(String contentBase64, java.security.Key key, int segmentSize) {
        try {
            // ???????????????
            byte[] srcBytes = Base64Utils.decodeFromString(contentBase64);
            // Cipher??????????????????????????????????????????RSA
//            Cipher deCipher = Cipher.getInstance("RSA");
            Cipher deCipher = Cipher.getInstance(transformation0);
            // ??????????????????Cipher?????????????????????
            deCipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decBytes = null;//deCipher.doFinal(srcBytes);
            if (segmentSize > 0){
                decBytes = cipherDoFinal(deCipher, srcBytes, segmentSize);} //????????????
            else{
                decBytes = deCipher.doFinal(srcBytes);}

            String decrytStr = new String(decBytes);
            return decrytStr;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * ?????????
     */
    public static class KeyPairInfo {
        String privateKey;
        String publicKey;
        int keySize = 0;

        public KeyPairInfo(int keySize) {
            setKeySize(keySize);
        }

        public KeyPairInfo(String publicKey, String privateKey) {
            setPrivateKey(privateKey);
            setPublicKey(publicKey);
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public int getKeySize() {
            return keySize;
        }

        public void setKeySize(int keySize) {
            this.keySize = keySize;
        }
    }

    public static void main(String[] args) {
        String content="wocaonimei";
        String pubKey= "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAId2P5T9ltHFxNK8ndg3oAFDluvTb3BsHGTBOSpICPfyMZsPMbuJw5R2xuUnRiVR2Zja3o8OCwzYg5owXWya9skCAwEAAQ==";
        String priKey="MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAh3Y/lP2W0cXE0ryd2DegAUOW69NvcGwcZME5KkgI9/Ixmw8xu4nDlHbG5SdGJVHZmNrejw4LDNiDmjBdbJr2yQIDAQABAkBz+HVIra3wG3t820PbNwwB6QaNEO/H9JZ+X7n8C7253t1NOlus2CalvewjrWl6ZbYojcwfJKL6sg6Q+JHp+XNdAiEAvqZKPVoZt1ZlFvJDomITiBTUBEwfFfPG4ZAEeZBjXS8CIQC15S4cocXPk7/n47KLUjOPw3ncm2H26+cGclU7uyGdhwIgOUdowqoRU93nHU/INj9VMutfD7N3G3dUZ2yHi6Zv1A0CIQCRCYJAQFo7j0NpQu1eHBiTHLoxxxBRVH8ta8M80pUWRwIgfdFt2vuMKDYhBJzDebiR38UjPRNPV+n66zJ48q0Te0o=";
//        String jiami="ZMOfwoZAWcOFw7AiKkPCt8O2woQHwrURQ3Y/wpE6HcOuB8KZPcKrBxnCkcO0A1vDr8OkwqrDpSIwNMKcwprDmsKyF1pqAsK4wrMSw4vCgk/Cg37Ct8O7IsK9wotwwrp7";
        //????????????
        String jiami = encipher(content, pubKey);

        System.out.println(jiami);
        String jiemi = decipher(jiami, priKey);
        System.out.println(jiemi);

    }
}
