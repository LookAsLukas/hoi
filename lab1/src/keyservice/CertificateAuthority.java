package keyservice;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class CertificateAuthority {
    private final X500Name issuer;
    private final PrivateKey signingKey;
    private final long validityMillis;
    private final SecureRandom random = new SecureRandom();

    public CertificateAuthority(String issuer, PrivateKey signingKey, int validityDays) {
        this.issuer = parseX500Name(issuer);
        this.signingKey = signingKey;
        this.validityMillis = Math.multiplyExact((long) validityDays, 86_400_000L);
    }

    public KeyMaterial issue(String subjectName, KeyPair keyPair) throws Exception {
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, subjectName)
                .build();
        BigInteger serial = new BigInteger(160, random).abs();
        if (serial.signum() == 0) {
            serial = BigInteger.ONE;
        }

        Date notBefore = new Date(System.currentTimeMillis() - 300_000L);
        Date notAfter = new Date(notBefore.getTime() + validityMillis);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(signingKey);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
        String privateKeyPem = PemFiles.toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        String certificatePem = PemFiles.toPem("CERTIFICATE", certificate.getEncoded());
        return new KeyMaterial(privateKeyPem, certificatePem);
    }

    public static X500Name parseX500Name(String value) {
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Name must not be empty");
        }
        try {
            return new X500Name(trimmed);
        } catch (IllegalArgumentException e) {
            return new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, trimmed)
                    .build();
        }
    }

    public static X509Certificate createSelfSignedCa(X500Name name, KeyPair keyPair, int validityDays,
            SecureRandom random) throws Exception {
        BigInteger serial = new BigInteger(160, random).abs();
        if (serial.signum() == 0) {
            serial = BigInteger.ONE;
        }
        Date notBefore = new Date(System.currentTimeMillis() - 300_000L);
        Date notAfter = new Date(notBefore.getTime() + Math.multiplyExact((long) validityDays, 86_400_000L));
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }
}
