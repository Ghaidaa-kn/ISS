//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class GenerateKeys {
    String privatekey;
    String publicket;
    KeyPairGenerator kpg;

    GenerateKeys() {
    }

    public void Geenertateandstore(String fileName1, String fileName2) throws NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = (RSAPublicKeySpec)fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
        saveToFile(fileName1, pub.getModulus(), pub.getPublicExponent());
        RSAPrivateKeySpec priv = (RSAPrivateKeySpec)fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
        saveToFile(fileName2, priv.getModulus(), priv.getPrivateExponent());
    }

    public static PublicKey readPublicKey(String fileName) throws Exception {
        InputStream in = new FileInputStream(fileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));

        PublicKey var8;
        try {
            BigInteger m = (BigInteger)oin.readObject();
            BigInteger e = (BigInteger)oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            var8 = pubKey;
        } catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | IOException var12) {
            throw new Exception(var12);
        } finally {
            oin.close();
        }

        return var8;
    }

    public static PrivateKey readPrivateKey(String fileName) throws Exception {
        FileInputStream in = new FileInputStream(fileName);

        try {
            ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
            Throwable var3 = null;

            PrivateKey var9;
            try {
                BigInteger m = (BigInteger)oin.readObject();
                BigInteger e = (BigInteger)oin.readObject();
                RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
                KeyFactory fact = KeyFactory.getInstance("RSA");
                PrivateKey privaKey = fact.generatePrivate(keySpec);
                var9 = privaKey;
            } catch (Throwable var19) {
                var3 = var19;
                throw var19;
            } finally {
                if (oin != null) {
                    if (var3 != null) {
                        try {
                            oin.close();
                        } catch (Throwable var18) {
                            var3.addSuppressed(var18);
                        }
                    } else {
                        oin.close();
                    }
                }

            }

            return var9;
        } catch (Exception var21) {
            throw new Exception(var21);
        }
    }

    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws Exception {
        try {
            ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
            Throwable var4 = null;

            try {
                oout.writeObject(mod);
                oout.writeObject(exp);
            } catch (Throwable var14) {
                var4 = var14;
                throw var14;
            } finally {
                if (oout != null) {
                    if (var4 != null) {
                        try {
                            oout.close();
                        } catch (Throwable var13) {
                            var4.addSuppressed(var13);
                        }
                    } else {
                        oout.close();
                    }
                }

            }

        } catch (Exception var16) {
            throw new Exception(var16);
        }
    }

    public String getpublic(PublicKey pub) throws NoSuchAlgorithmException {
        this.publicket = Base64.getEncoder().encodeToString(pub.getEncoded());
        return this.publicket;
    }

    public String getprivate(PrivateKey pri) throws NoSuchAlgorithmException {
        this.privatekey = Base64.getEncoder().encodeToString(pri.getEncoded());
        return this.privatekey;
    }
}
