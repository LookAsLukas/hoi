package keyservice;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.EnumSet;
import java.util.Set;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public final class PemFiles {
    private PemFiles() {
    }

    public static PrivateKey readPrivateKey(Path path) throws IOException {
        try (PEMParser parser = new PEMParser(Files.newBufferedReader(path, StandardCharsets.US_ASCII))) {
            Object object;
            while ((object = parser.readObject()) != null) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                if (object instanceof PrivateKeyInfo info) {
                    return converter.getPrivateKey(info);
                }
                if (object instanceof PEMKeyPair pair) {
                    return converter.getKeyPair(pair).getPrivate();
                }
            }
        }

        byte[] encoded = Files.readAllBytes(path);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IOException("No RSA private key found in " + path, e);
        }
    }

    public static String toPem(String type, byte[] encoded) throws IOException {
        StringWriter writer = new StringWriter();
        try (PemWriter pem = new PemWriter(writer)) {
            pem.writeObject(new PemObject(type, encoded));
        }
        return writer.toString();
    }

    public static void writePem(Path path, String type, byte[] encoded, boolean privateFile) throws IOException {
        Files.writeString(path, toPem(type, encoded), StandardCharsets.US_ASCII);
        if (privateFile) {
            setPermissions(path, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } else {
            setPermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ));
        }
    }

    public static void setPermissions(Path path, Set<PosixFilePermission> permissions) {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException | IOException ignored) {
        }
    }
}
