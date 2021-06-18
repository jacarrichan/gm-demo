package com.jacarrichan.demo.gm.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

/**
 * SM2 非对称加密
 */
public class SM2Utils {

    private transient static Logger logger = LoggerFactory.getLogger(SM2Utils.class);

    public static ThreadLocal<Signature> signature = ThreadLocal.withInitial(() -> {
        try {
            return Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    });

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair createKeyPair() {
        // 获取SM2 椭圆曲线推荐参数
        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造EC 算法参数
        ECNamedCurveParameterSpec sm2Spec = new ECNamedCurveParameterSpec(
                // 设置SM2 算法的 OID
                GMObjectIdentifiers.sm2p256v1.toString()
                // 设置曲线方程
                , ecParameters.getCurve()
                // 椭圆曲线G点
                , ecParameters.getG()
                // 大整数N
                , ecParameters.getN());
        try {
            // 创建 密钥对生成器
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            // 使用SM2的算法区域初始化密钥生成器
            gen.initialize(sm2Spec, new SecureRandom());
            // 获取密钥对
            KeyPair keyPair = gen.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 签名
     *
     * @param privateKey 签名私钥
     * @param plainText  明文
     * @return
     */
    public static String sign(PrivateKey privateKey, String plainText) {
        try {
            signature.get().initSign(privateKey);
            signature.get().update(plainText.getBytes());
            byte[] bytes = signature.get().sign();
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            logger.error("[SM2Utils][sign]Get signature failure.", e);
        }
        return null;
    }

    /**
     * 签名
     *
     * @param privateKeyStr 签名私钥
     * @param plainText     明文
     * @return
     */
    public static String sign(String privateKeyStr, String plainText) {

        try {
            byte[] privateBytes = Base64.decodeBase64(privateKeyStr);
            PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(privateBytes));
            signature.get().initSign(privateKey);
            signature.get().update(plainText.getBytes());
            byte[] bytes = signature.get().sign();
            return Base64.encodeBase64String(bytes);
        } catch (Exception e) {
            logger.error("[SM2Utils][sign]Get signature failure.", e);
        }

        return null;

    }

    /**
     * 验证签名
     *
     * @param publicKey  签名公钥
     * @param signString 签名结果
     * @param plainText  明文
     * @return
     */
    public static boolean verifySign(PublicKey publicKey, String signString, String plainText) {
        boolean result = false;
        try {
            signature.get().initVerify(publicKey);
            signature.get().update(plainText.getBytes());
            result = signature.get().verify(Base64.decodeBase64(signString));
        } catch (Exception e) {
            logger.error("[SM2Utils][sign]Verify signature failure.", e);
        }
        return result;
    }

    /**
     * 验证签名
     *
     * @param publicKeyStr 签名公钥
     * @param sign         签名结果
     * @param plainText    明文
     * @return
     */
    public static boolean verifySign(String publicKeyStr, String sign, String plainText) {

        boolean result = false;
        try {
            byte[] publicBytes = Base64.decodeBase64(publicKeyStr);
            PublicKey publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(publicBytes));
            signature.get().initVerify(publicKey);
            signature.get().update(plainText.getBytes());
            result = signature.get().verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            logger.error("[SM2Utils][sign]Verify signature failure.", e);
        }

        return result;

    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = SM2Utils.createKeyPair();
        SM2KeyPair sm2KeyPair = new SM2KeyPair();
        sm2KeyPair.setKeyId("key1");
        sm2KeyPair.setPublicKey(Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
        sm2KeyPair.setPrivateKey(Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
        String hexPrivateKey = Hex.encodeHexString(((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray());
        String hexPublicKey = Hex.encodeHexString(((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false));
        System.out.println(hexPrivateKey);
        System.out.println(hexPublicKey);
        KeyPair keyPair2 = SM2Utils.createKeyPair();
        SM2KeyPair sm2KeyPair2 = new SM2KeyPair();
        sm2KeyPair2.setKeyId("key2");
        sm2KeyPair2.setPublicKey(Base64.encodeBase64String(keyPair2.getPublic().getEncoded()));
        sm2KeyPair2.setPrivateKey(Base64.encodeBase64String(keyPair2.getPrivate().getEncoded()));

        String rawText1 = "test-test-test";
        String signKey1 = SM2Utils.sign(sm2KeyPair.getPrivateKey(), rawText1);
        boolean verify = SM2Utils.verifySign(sm2KeyPair.getPublicKey(), signKey1, rawText1);
        if (!verify) {
            System.out.println(false);
        }
    }

}