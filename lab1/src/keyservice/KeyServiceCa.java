package keyservice;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class KeyServiceCa {
    public static void main(String[] args) {
        try {
            Options options = Options.parse(args);
            if (options.help()) {
                usage();
                return;
            }

            Security.addProvider(new BouncyCastleProvider());
            Files.createDirectories(options.outDir());
            Path keyPath = options.outDir().resolve("ca.key");
            Path certificatePath = options.outDir().resolve("ca.crt");
            if (!options.force() && (Files.exists(keyPath) || Files.exists(certificatePath))) {
                throw new IllegalArgumentException("CA files already exist; use --force to overwrite");
            }

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(options.bits());

            KeyPair keyPair = generator.generateKeyPair();
            X500Name name = CertificateAuthority.parseX500Name(options.issuer());
            X509Certificate certificate = CertificateAuthority.createSelfSignedCa(
                    name, keyPair, options.days(), new SecureRandom());
            PemFiles.writePem(keyPath, "PRIVATE KEY", keyPair.getPrivate().getEncoded(), true);
            PemFiles.writePem(certificatePath, "CERTIFICATE", certificate.getEncoded(), false);
            System.out.println("Created CA private key: " + keyPath.toAbsolutePath());
            System.out.println("Created CA certificate: " + certificatePath.toAbsolutePath());
            System.out.println("Issuer: " + name);
            System.out.println("Start the server with --issuer \"" + name + "\".");
        } catch (Exception e) {
            System.err.println("CA setup failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void usage() {
        System.out.println("""
                Usage: KeyServiceCa [options]

                Options:
                  --out DIR          output directory (default: ca)
                  --issuer NAME      issuer distinguished name (default: CN=RSA Key Service CA,O=Demo)
                  --bits N           RSA key size for the CA key (default: 4096)
                  --days N           CA certificate validity in days (default: 3650)
                  --force            overwrite existing ca.key and ca.crt
                  --help             show this help
                """);
    }

    private record Options(Path outDir, String issuer, int bits, int days, boolean force, boolean help) {
        static Options parse(String[] args) {
            Path outDir = Path.of("ca");
            String issuer = "CN=RSA Key Service CA,O=Demo";
            int bits = 4096;
            int days = 3650;
            boolean force = false;
            boolean help = false;
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--out" -> outDir = Path.of(value(args, ++i, "--out"));
                    case "--issuer" -> issuer = value(args, ++i, "--issuer");
                    case "--bits" -> bits = Integer.parseInt(value(args, ++i, "--bits"));
                    case "--days" -> days = Integer.parseInt(value(args, ++i, "--days"));
                    case "--force" -> force = true;
                    case "--help", "-h" -> help = true;
                    default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
                }
            }
            if (bits < 2048) {
                throw new IllegalArgumentException("--bits must be at least 2048");
            }
            if (days < 1) {
                throw new IllegalArgumentException("--days must be positive");
            }
            return new Options(outDir, issuer, bits, days, force, help);
        }

        private static String value(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }
    }
}
