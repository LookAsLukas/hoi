package keyservice;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class LoadTest {
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
            System.err.println("Invalid name");
            System.exit(2);
            return;
        }

        try {
            ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
            List<Future<String>> results = new ArrayList<>();
            for (int i = 0; i < options.clients(); i++) {
                results.add(executor.submit(() -> request(options)));
            }

            Set<String> hashes = new HashSet<>();
            for (Future<String> result : results) {
                hashes.add(result.get());
            }
            executor.shutdown();

            if (hashes.size() != 1) {
                System.err.println("Clients received different key material");
                System.exit(1);
            }
            System.out.println("OK: " + options.clients() + " client(s) received identical key material");
        } catch (Exception e) {
            System.err.println("Load test failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String request(Options options) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(options.host(), options.port()), 10_000);
            socket.setSoTimeout(Math.toIntExact(options.timeoutSeconds() * 1000L));

            OutputStream out = socket.getOutputStream();
            out.write(options.name().getBytes(StandardCharsets.US_ASCII));
            out.write(0);
            out.flush();

            if (options.delaySeconds() > 0) {
                Thread.sleep(Math.multiplyExact(options.delaySeconds(), 1000L));
            }

            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            Protocol.Response response = Protocol.read(in);
            if (response.status() != Protocol.STATUS_OK) {
                throw new IllegalStateException(response.error());
            }

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(response.privateKeyPem());
            digest.update(response.certificatePem());
            return HexFormat.of().formatHex(digest.digest());
        }
    }

    private static void usage() {
        System.out.println("""
                Usage: LoadTest [options]

                Options:
                  --name NAME       client name (required)
                  --host HOST       server host (default: 127.0.0.1)
                  --port N          server port (default: 9090)
                  --clients N       number of concurrent clients (default: 100)
                  --delay N         sleep N seconds after sending in every client
                  --timeout N       socket read timeout in seconds (default: 600)
                  --help            show this help
                """);
    }

    private record Options(String name, String host, int port, int clients, long delaySeconds,
            long timeoutSeconds, boolean help) {
        static Options parse(String[] args) {
            String name = null;
            String host = "127.0.0.1";
            int port = 9090;
            int clients = 100;
            long delaySeconds = 0;
            long timeoutSeconds = 600;
            boolean help = false;
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--name" -> name = value(args, ++i, "--name");
                    case "--host" -> host = value(args, ++i, "--host");
                    case "--port" -> port = Integer.parseInt(value(args, ++i, "--port"));
                    case "--clients" -> clients = Integer.parseInt(value(args, ++i, "--clients"));
                    case "--delay" -> delaySeconds = Long.parseLong(value(args, ++i, "--delay"));
                    case "--timeout" -> timeoutSeconds = Long.parseLong(value(args, ++i, "--timeout"));
                    case "--help", "-h" -> help = true;
                    default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
                }
            }
            if (!help && name == null) {
                throw new IllegalArgumentException("--name is required");
            }
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("--port must be between 1 and 65535");
            }
            if (clients < 1) {
                throw new IllegalArgumentException("--clients must be positive");
            }
            if (delaySeconds < 0) {
                throw new IllegalArgumentException("--delay must not be negative");
            }
            if (timeoutSeconds < 1) {
                throw new IllegalArgumentException("--timeout must be positive");
            }
            return new Options(name, host, port, clients, delaySeconds, timeoutSeconds, help);
        }

        private static String value(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }
    }
}
