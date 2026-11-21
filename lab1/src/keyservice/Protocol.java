package keyservice;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Protocol {
    public static final int MAGIC = 0x4b525331;
    public static final int STATUS_OK = 0;
    public static final int STATUS_ERROR = 1;
    public static final int MAX_FIELD_BYTES = 1_048_576;
    public static final int MAX_NAME_BYTES = 255;
    public static final int HEADER_BYTES = 20;

    private Protocol() {
    }

    public static void writeSuccess(OutputStream out, KeyMaterial material) throws IOException {
        byte[] key = material.privateKeyPem().getBytes(StandardCharsets.US_ASCII);
        byte[] certificate = material.certificatePem().getBytes(StandardCharsets.US_ASCII);
        DataOutputStream data = new DataOutputStream(out);
        data.writeInt(MAGIC);
        data.writeInt(STATUS_OK);
        data.writeInt(key.length);
        data.writeInt(certificate.length);
        data.writeInt(0);
        data.write(key);
        data.write(certificate);
        data.flush();
    }

    public static void writeError(OutputStream out, String message) throws IOException {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_FIELD_BYTES) {
            bytes = Arrays.copyOf(bytes, MAX_FIELD_BYTES);
        }
        DataOutputStream data = new DataOutputStream(out);
        data.writeInt(MAGIC);
        data.writeInt(STATUS_ERROR);
        data.writeInt(0);
        data.writeInt(0);
        data.writeInt(bytes.length);
        data.write(bytes);
        data.flush();
    }

    public static Response read(InputStream in) throws IOException {
        DataInputStream data = new DataInputStream(in);
        int magic;
        try {
            magic = data.readInt();
        } catch (EOFException e) {
            throw new IOException("Connection closed before the response header", e);
        }

        if (magic != MAGIC) {
            throw new IOException("Invalid response magic: 0x" + Integer.toHexString(magic));
        }

        int status = data.readInt();
        int keyLength = data.readInt();
        int certificateLength = data.readInt();
        int messageLength = data.readInt();
        if (keyLength < 0 || keyLength > MAX_FIELD_BYTES
                || certificateLength < 0 || certificateLength > MAX_FIELD_BYTES
                || messageLength < 0 || messageLength > MAX_FIELD_BYTES) {
            throw new IOException("Invalid response field length");
        }
        byte[] key = data.readNBytes(keyLength);
        byte[] certificate = data.readNBytes(certificateLength);
        byte[] message = data.readNBytes(messageLength);
        if (key.length != keyLength || certificate.length != certificateLength
                || message.length != messageLength) {
            throw new EOFException("Connection closed in the middle of the response");
        }
        if (status == STATUS_OK) {
            return new Response(status, key, certificate, "");
        }
        if (status == STATUS_ERROR) {
            return new Response(status, key, certificate, new String(message, StandardCharsets.UTF_8));
        }
        throw new IOException("Unknown response status: " + status);
    }

    public static boolean isValidName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_NAME_BYTES) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char value = name.charAt(i);
            if (value == 0 || value > 0x7f) {
                return false;
            }
        }
        return true;
    }

    public record Response(int status, byte[] privateKeyPem, byte[] certificatePem, String error) {
    }
}
