//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

public class DSA {
    public DSA() {
    }

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA");
        keyGenerator.initialize(1024);
        return keyGenerator.genKeyPair();
    }

    public static byte[] sign(DSAPrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature signAlgorithm = Signature.getInstance("DSA");
        byte[] Text = null;
        Text = message.getBytes("UTF-8");
        signAlgorithm.initSign(privateKey);
        signAlgorithm.update(Text);
        return signAlgorithm.sign();
    }

    public static boolean verify(DSAPublicKey publicKey, String message, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        Signature verifyAlgorithm = Signature.getInstance("DSA");
        byte[] Text = null;
        Text = message.getBytes("UTF-8");
        verifyAlgorithm.initVerify(publicKey);
        verifyAlgorithm.update(Text);
        return verifyAlgorithm.verify(signature);
    }
}
