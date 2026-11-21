package keyservice;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class KeyServiceServer implements AutoCloseable {
    private final Options options;
    private final CertificateAuthority authority;
    private final ConcurrentHashMap<String, CompletableFuture<KeyMaterial>> cache = new ConcurrentHashMap<>();
    private final BlockingQueue<GenerationTask> generationQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<SendTask> sendQueue = new LinkedBlockingQueue<>();
    private final ExecutorService sendExecutor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final List<Thread> generationWorkers = new ArrayList<>();
    private final Map<SocketChannel, Connection> connections = new ConcurrentHashMap<>();
    private Selector selector;
    private ServerSocketChannel serverChannel;
    private Thread sendDispatcher;

    private KeyServiceServer(Options options, CertificateAuthority authority) {
        this.options = options;
        this.authority = authority;
    }

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

        Security.addProvider(new BouncyCastleProvider());
        try {
            if (!Files.isReadable(options.signingKey())) {
                throw new IllegalArgumentException("Signing key is not readable: " + options.signingKey());
            }

            PrivateKey signingKey = PemFiles.readPrivateKey(options.signingKey());
            CertificateAuthority authority = new CertificateAuthority(
                    options.issuer(), signingKey, options.validityDays());
            try (KeyServiceServer server = new KeyServiceServer(options, authority)) {
                Runtime.getRuntime().addShutdownHook(new Thread(server::close, "key-service-shutdown"));
                server.start();
            }
        } catch (Exception e) {
            System.err.println("Server failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private void start() throws IOException {
        selector = Selector.open();
        InetAddress bindAddress = InetAddress.getByName(options.bindAddress());
        StandardProtocolFamily family = bindAddress instanceof Inet4Address
                ? StandardProtocolFamily.INET
                : StandardProtocolFamily.INET6;

        serverChannel = ServerSocketChannel.open(family);
        serverChannel.setOption(StandardSocketOptions.SO_REUSEADDR, true);
        serverChannel.bind(new InetSocketAddress(bindAddress, options.port()), 1024);
        serverChannel.configureBlocking(false);
        serverChannel.register(selector, SelectionKey.OP_ACCEPT);

        startGenerators();
        startSendDispatcher();

        InetSocketAddress local = (InetSocketAddress) serverChannel.getLocalAddress();
        log("Listening on %s:%d with %d generation thread(s)",
                local.getAddress().getHostAddress(), local.getPort(), options.generationThreads());
        log("Issuer: %s", options.issuer());
        log("Signing key: %s", options.signingKey().toAbsolutePath());
        try {
            while (running.get()) {
                selector.select();
                if (!running.get()) {
                    break;
                }

                List<PendingRequest> pending = new ArrayList<>();
                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (!key.isValid()) {
                        continue;
                    }

                    if (key.isAcceptable()) {
                        accept();
                    } else if (key.isReadable()) {
                        read(key, pending);
                    }
                }

                if (!pending.isEmpty()) {
                    selector.selectNow();
                    selector.selectedKeys().clear();

                    for (PendingRequest request : pending) {
                        prepareForSending(request);
                    }
                }
            }
        } catch (ClosedSelectorException e) {
            if (running.get()) {
                throw e;
            }
        } finally {
            close();
        }
    }

    private void accept() {
        while (true) {
            SocketChannel channel;
            try {
                channel = serverChannel.accept();
            } catch (IOException e) {
                log("Accept failed: %s", e.getMessage());
                return;
            }

            if (channel == null) {
                return;
            }

            try {
                channel.configureBlocking(false);
                channel.setOption(StandardSocketOptions.TCP_NODELAY, true);
                channel.setOption(StandardSocketOptions.SO_KEEPALIVE, true);

                Connection connection = new Connection(channel);
                channel.register(selector, SelectionKey.OP_READ, connection);
                connections.put(channel, connection);
            } catch (IOException | RuntimeException e) {
                closeQuietly(channel);
            }
        }
    }

    private void read(SelectionKey key, List<PendingRequest> pending) {
        Connection connection = (Connection) key.attachment();
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        int count;
        try {
            count = connection.channel.read(buffer);
        } catch (IOException e) {
            closeConnection(key);
            return;
        }

        if (count < 0) {
            closeConnection(key);
            return;
        }
        if (count == 0) {
            return;
        }

        buffer.flip();
        while (buffer.hasRemaining()) {
            int value = buffer.get() & 0xff;
            if (value == 0) {
                String name = connection.name.toString(StandardCharsets.US_ASCII);
                String error = null;
                if (connection.invalid) {
                    error = "Name must contain only US-ASCII characters";
                } else if (!Protocol.isValidName(name)) {
                    error = "Name must be non-empty and at most " + Protocol.MAX_NAME_BYTES + " bytes";
                }

                detach(key, connection, pending, name, error);
                return;
            }

            if (value > 0x7f) {
                connection.invalid = true;
            }

            if (connection.length >= Protocol.MAX_NAME_BYTES) {
                detach(key, connection, pending, null,
                        "Name is too long; maximum is " + Protocol.MAX_NAME_BYTES + " bytes");
                return;
            }

            connection.name.write(value);
            connection.length++;
        }
    }

    private void detach(SelectionKey key, Connection connection, List<PendingRequest> pending,
            String name, String error) {
        key.cancel();
        connections.remove(connection.channel);
        pending.add(new PendingRequest(connection.channel, name, error));
    }

    private void prepareForSending(PendingRequest request) {
        try {
            request.channel().configureBlocking(true);
        } catch (IOException | RuntimeException e) {
            closeQuietly(request.channel());
            return;
        }

        if (request.error() != null) {
            enqueue(new SendTask(request.channel(), null, request.error()));
        } else {
            requestKeys(request.channel(), request.name());
        }
    }

    private void requestKeys(SocketChannel channel, String name) {
        CompletableFuture<KeyMaterial> future = cache.computeIfAbsent(name, key -> {
            CompletableFuture<KeyMaterial> created = new CompletableFuture<>();
            generationQueue.add(new GenerationTask(key, created));
            log("Queued generation for \"%s\"", key);
            return created;
        });

        future.whenComplete((material, error) -> {
            if (error != null) {
                enqueue(new SendTask(channel, null, rootMessage(error)));
            } else {
                enqueue(new SendTask(channel, material, null));
            }
        });
    }

    private void enqueue(SendTask task) {
        if (!sendQueue.offer(task)) {
            closeQuietly(task.channel());
        }
    }

    private void startGenerators() {
        for (int i = 1; i <= options.generationThreads(); i++) {
            int worker = i;
            Thread thread = Thread.ofPlatform()
                    .name("rsa-generator-" + worker)
                    .daemon(true)
                    .start(this::generationLoop);
            generationWorkers.add(thread);
        }
    }

    private void generationLoop() {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(8192);
        } catch (Exception e) {
            log("Cannot initialize RSA key generator: %s", e.getMessage());
            return;
        }

        while (running.get()) {
            GenerationTask task;
            try {
                task = generationQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }

            long started = System.nanoTime();
            try {
                KeyPair keyPair = generator.generateKeyPair();
                KeyMaterial material = authority.issue(task.name(), keyPair);
                task.future().complete(material);
                log("Generated 8192-bit RSA key and certificate for \"%s\" in %.1f s",
                        task.name(), Duration.ofNanos(System.nanoTime() - started).toMillis() / 1000.0);
            } catch (Throwable e) {
                cache.remove(task.name(), task.future());
                task.future().completeExceptionally(e);
                log("Generation failed for \"%s\": %s", task.name(), rootMessage(e));
            }
        }
    }

    private void startSendDispatcher() {
        sendDispatcher = Thread.ofPlatform()
                .name("response-dispatcher")
                .daemon(true)
                .start(() -> {
                    while (running.get()) {
                        SendTask task;
                        try {
                            task = sendQueue.take();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }

                        try {
                            sendExecutor.submit(() -> send(task));
                        } catch (RejectedExecutionException e) {
                            closeQuietly(task.channel());
                        }
                    }
                });
    }

    private void send(SendTask task) {
        try (SocketChannel channel = task.channel()) {
            OutputStream out = Channels.newOutputStream(channel);
            if (task.error() != null) {
                Protocol.writeError(out, task.error());
            } else {
                Protocol.writeSuccess(out, task.material());
            }

            out.flush();
            log("Sent response to %s", channel.getRemoteAddress());
        } catch (IOException e) {
            log("Send failed: %s", e.getMessage());
        }
    }

    private void closeConnection(SelectionKey key) {
        Connection connection = (Connection) key.attachment();
        key.cancel();
        connections.remove(connection.channel);
        closeQuietly(connection.channel);
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        if (selector != null) {
            selector.wakeup();
        }
        closeQuietly(serverChannel);
        for (Connection connection : new ArrayList<>(connections.values())) {
            closeQuietly(connection.channel);
        }
        connections.clear();
        for (Thread worker : generationWorkers) {
            worker.interrupt();
        }
        if (sendDispatcher != null) {
            sendDispatcher.interrupt();
        }
        sendExecutor.shutdownNow();
        if (selector != null) {
            try {
                selector.close();
            } catch (IOException ignored) {
            }
        }
        log("Server stopped");
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }

        try {
            closeable.close();
        } catch (Exception ignored) {
        }
    }

    private static String rootMessage(Throwable error) {
        Throwable current = error;
        while ((current instanceof CompletionException || current instanceof ExecutionException)
                && current.getCause() != null) {
            current = current.getCause();
        }

        String message = current.getMessage();
        return message == null || message.isBlank() ? current.getClass().getSimpleName() : message;
    }

    private static void log(String format, Object... args) {
        System.out.printf("%s %s%n", Instant.now(), String.format(format, args));
    }

    private static void usage() {
        System.out.println("""
                Usage: KeyServiceServer [options]

                Options:
                  --port N             TCP port to listen on (default: 9090)
                  --bind ADDRESS       bind address (default: 0.0.0.0)
                  --gen-threads N      fixed RSA generation thread count (default: CPU count)
                  --issuer NAME        issuer distinguished name (default: CN=RSA Key Service CA,O=Demo)
                  --signing-key FILE   PKCS#8/PEM private key used for signing (default: ca/ca.key)
                  --validity-days N    leaf certificate validity in days (default: 365)
                  --help               show this help
                """);
    }

    private static final class Connection {
        private final SocketChannel channel;
        private final ByteArrayOutputStream name;
        private int length;
        private boolean invalid;

        private Connection(SocketChannel channel) {
            this.channel = channel;
            this.name = new ByteArrayOutputStream(Protocol.MAX_NAME_BYTES);
        }
    }

    private record PendingRequest(SocketChannel channel, String name, String error) { }

    private record GenerationTask(String name, CompletableFuture<KeyMaterial> future) { }

    private record SendTask(SocketChannel channel, KeyMaterial material, String error) { }

    private record Options(String bindAddress, int port, int generationThreads, String issuer,
            Path signingKey, int validityDays, boolean help) {
        static Options parse(String[] args) {
            String bindAddress = "0.0.0.0";
            int port = 9090;
            int generationThreads = Runtime.getRuntime().availableProcessors();
            String issuer = "CN=RSA Key Service CA,O=Demo";
            Path signingKey = Path.of("ca/ca.key");
            int validityDays = 365;
            boolean help = false;
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--port" -> port = Integer.parseInt(value(args, ++i, "--port"));
                    case "--bind" -> bindAddress = value(args, ++i, "--bind");
                    case "--gen-threads" -> generationThreads = Integer.parseInt(value(args, ++i, "--gen-threads"));
                    case "--issuer" -> issuer = value(args, ++i, "--issuer");
                    case "--signing-key" -> signingKey = Path.of(value(args, ++i, "--signing-key"));
                    case "--validity-days" -> validityDays = Integer.parseInt(value(args, ++i, "--validity-days"));
                    case "--help", "-h" -> help = true;
                    default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
                }
            }
            if (port < 0 || port > 65535) {
                throw new IllegalArgumentException("--port must be between 0 and 65535");
            }
            if (generationThreads < 1) {
                throw new IllegalArgumentException("--gen-threads must be positive");
            }
            if (validityDays < 1) {
                throw new IllegalArgumentException("--validity-days must be positive");
            }
            return new Options(bindAddress, port, generationThreads, issuer, signingKey, validityDays, help);
        }

        private static String value(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }
    }
}
