package keyservice;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

public final class KeyClient {
    public static void main(String[] args) {
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            usage();
            System.exit(2);
            return;
        }

        if (options.help()) {
            usage();
            return;
        }

        if (!Protocol.isValidName(options.name())) {
            System.err.println("Name must be non-empty US-ASCII text of at most "
                    + Protocol.MAX_NAME_BYTES + " bytes");
            System.exit(2);
            return;
        }

        try {
            int exitCode = run(options);
            if (exitCode != 0) {
                System.exit(exitCode);
            }
        } catch (Exception e) {
            System.err.println("Client failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static int run(Options options) throws Exception {
        byte[] nameBytes = options.name().getBytes(StandardCharsets.US_ASCII);
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(options.host(), options.port()),
                    Math.toIntExact(options.connectTimeoutSeconds() * 1000L));
            socket.setSoTimeout(Math.toIntExact(options.readTimeoutSeconds() * 1000L));
            OutputStream out = socket.getOutputStream();
            out.write(nameBytes);
            out.write(0);
            out.flush();
            System.out.println("Request sent for name: " + options.name());

            if (options.delaySeconds() > 0) {
                System.out.println("Sleeping for " + options.delaySeconds() + " second(s) before reading");
                Thread.sleep(Math.multiplyExact(options.delaySeconds(), 1000L));
            }
            if (options.abort()) {
                socket.setSoLinger(true, 0);
                System.out.println("Aborting without reading the response");
                return 0;
            }

            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            Protocol.Response response = Protocol.read(in);
            if (response.status() != Protocol.STATUS_OK) {
                System.err.println("Server error: " + response.error());
                return 2;
            }

            Path outDir = options.outDir().toAbsolutePath().normalize();
            Files.createDirectories(outDir);
            String base = sanitize(options.name());
            Path keyPath = outDir.resolve(base + ".key");
            Path certificatePath = outDir.resolve(base + ".crt");
            Files.write(keyPath, response.privateKeyPem());
            Files.write(certificatePath, response.certificatePem());
            PemFiles.setPermissions(keyPath, EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            PemFiles.setPermissions(certificatePath, EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ));
            System.out.println("Saved private key: " + keyPath);
            System.out.println("Saved certificate: " + certificatePath);
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(response.certificatePem()));
            System.out.println("Certificate subject: " + certificate.getSubjectX500Principal());
            System.out.println("Certificate issuer: " + certificate.getIssuerX500Principal());
            return 0;
        }
    }

    private static String sanitize(String name) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < name.length() && result.length() < 100; i++) {
            char value = name.charAt(i);
            if ((value >= 'a' && value <= 'z')
                    || (value >= 'A' && value <= 'Z')
                    || (value >= '0' && value <= '9')
                    || value == '.'
                    || value == '-'
                    || value == '_') {
                result.append(value);
            } else {
                result.append('_');
            }
        }

        if (result.isEmpty()) {
            result.append("key");
        }

        if (result.charAt(0) == '.') {
            result.insert(0, '_');
        }

        return result.toString();
    }

    private static void usage() {
        System.out.println("""
                Usage: KeyClient [options] [NAME [HOST [PORT]]]

                Options:
                  --name NAME             client name, US-ASCII
                  --host HOST             server host name or address (default: 127.0.0.1)
                  --port N                server TCP port (default: 9090)
                  --out-dir DIR           directory for .key and .crt files (default: .)
                  --delay N               sleep N seconds after sending before reading
                  --abort                 close immediately after sending instead of reading
                  --connect-timeout N     connect timeout in seconds (default: 10)
                  --read-timeout N        read timeout in seconds, 0 means no timeout (default: 0)
                  --help                  show this help
                """);
    }

    private record Options(String name, String host, int port, Path outDir, long delaySeconds,
            boolean abort, long connectTimeoutSeconds, long readTimeoutSeconds, boolean help) {
        static Options parse(String[] args) {
            String name = null;
            String host = null;
            Integer port = null;
            Path outDir = Path.of(".");
            long delaySeconds = 0;
            boolean abort = false;
            long connectTimeoutSeconds = 10;
            long readTimeoutSeconds = 0;
            boolean help = false;
            List<String> positional = new ArrayList<>();
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--name" -> name = value(args, ++i, "--name");
                    case "--host" -> host = value(args, ++i, "--host");
                    case "--port" -> port = Integer.parseInt(value(args, ++i, "--port"));
                    case "--out-dir" -> outDir = Path.of(value(args, ++i, "--out-dir"));
                    case "--delay" -> delaySeconds = Long.parseLong(value(args, ++i, "--delay"));
                    case "--abort", "--exit-after-send" -> abort = true;
                    case "--connect-timeout" ->
                            connectTimeoutSeconds = Long.parseLong(value(args, ++i, "--connect-timeout"));
                    case "--read-timeout" ->
                            readTimeoutSeconds = Long.parseLong(value(args, ++i, "--read-timeout"));
                    case "--help", "-h" -> help = true;
                    default -> {
                        if (args[i].startsWith("--")) {
                            throw new IllegalArgumentException("Unknown option: " + args[i]);
                        }
                        positional.add(args[i]);
                    }
                }
            }
            if (positional.size() > 3) {
                throw new IllegalArgumentException("Too many positional arguments");
            }
            if (name == null && !positional.isEmpty()) {
                name = positional.get(0);
            }
            if (host == null && positional.size() >= 2) {
                host = positional.get(1);
            }
            if (port == null && positional.size() >= 3) {
                port = Integer.parseInt(positional.get(2));
            }
            if (name == null && !help) {
                throw new IllegalArgumentException("--name is required");
            }
            if (host == null) {
                host = "127.0.0.1";
            }
            if (port == null) {
                port = 9090;
            }
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("--port must be between 1 and 65535");
            }
            if (delaySeconds < 0) {
                throw new IllegalArgumentException("--delay must not be negative");
            }
            if (connectTimeoutSeconds < 1) {
                throw new IllegalArgumentException("--connect-timeout must be positive");
            }
            if (readTimeoutSeconds < 0) {
                throw new IllegalArgumentException("--read-timeout must not be negative");
            }
            return new Options(name, host, port, outDir, delaySeconds, abort,
                    connectTimeoutSeconds, readTimeoutSeconds, help);
        }

        private static String value(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }
    }
}
