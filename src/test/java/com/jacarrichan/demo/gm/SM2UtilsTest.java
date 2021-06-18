package com.jacarrichan.demo.gm;

import com.jacarrichan.demo.gm.util.SM2KeyPair;
import com.jacarrichan.demo.gm.util.SM2Utils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.CONFIGURATION;

@Slf4j
public class SM2UtilsTest {
    @Test
    public void test() {
        KeyPair keyPair = SM2Utils.createKeyPair();
        SM2KeyPair sm2KeyPair = new SM2KeyPair();
        sm2KeyPair.setKeyId("key1");
        sm2KeyPair.setPublicKey(Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
        sm2KeyPair.setPrivateKey(Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
        String hexPrivateKey = Hex.encodeHexString(((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray());
        String hexPublicKey = Hex.encodeHexString(((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false));
        log.info("hexPrivateKey:{}", hexPrivateKey);
        log.info("hexPublicKey :{}", hexPublicKey);
        String rawText1 = "test-test-test";
        String signKey1 = SM2Utils.sign(sm2KeyPair.getPrivateKey(), rawText1);
        boolean result = SM2Utils.verifySign(rawText1, hexPublicKey, signKey1);
        log.info("verify sign  :{}", result);
    }

    /**
     * HEX key转 base64key
     */
    @Test
    public void test2() throws DecoderException {
        KeyPair keyPair = SM2Utils.createKeyPair();
        log.info(Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
        log.info(Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
        String hexPrivateKey = Hex.encodeHexString(((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray());
        String hexPublicKey = Hex.encodeHexString(((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false));
        log.info("hexPrivateKey:{}", hexPrivateKey);
        log.info("hexPublicKey :{}", hexPublicKey);
        //----------------------------------------------
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECDomainParameters ecDomainParameters = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        ECCurve curve = spec.getCurve();
        //---------------public  key
        byte[] publicValue = Hex.decodeHex(hexPublicKey);
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(publicValue, 1, x, 0, 32);
        System.arraycopy(publicValue, 33, y, 0, 32);
        BigInteger X = new BigInteger(1, x);
        BigInteger Y = new BigInteger(1, y);
        ECPoint Q = curve.createPoint(X, Y);
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(Q, ecDomainParameters);
        BCECPublicKey bcecPublicKey = new BCECPublicKey("EC", ecPublicKeyParameters, spec, CONFIGURATION);
        log.info(Base64.encodeBase64String(bcecPublicKey.getEncoded()));
        //---------------private  key
        byte[] value = Hex.decodeHex(hexPrivateKey);
        BigInteger d = new BigInteger(1, value);
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(d, ecDomainParameters);
        BCECPrivateKey bcecPrivateKey = new BCECPrivateKey("EC", ecPrivateKeyParameters, bcecPublicKey, spec, CONFIGURATION);
        log.info(Base64.encodeBase64String(bcecPrivateKey.getEncoded()));
    }
}
