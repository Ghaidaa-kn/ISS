//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class X509 implements Serializable {
    public X509() {
    }

    public static X509Certificate generateV1Certificate(PublicKey PK, PrivateKey PVK, String Name) throws InvalidKeyException, NoSuchProviderException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X509Principal("CN=SERVER"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000L));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000L));
        certGen.setSubjectDN(new X509Name("CN=" + Name));
        certGen.setPublicKey(PK);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        return certGen.generateX509Certificate(PVK);
    }

    public static void main(String[] args) throws Exception {
    }
}
