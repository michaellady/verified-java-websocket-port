import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.java_websocket.WebSocket;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.Framedata;
import org.java_websocket.framing.PingFrame;
import org.java_websocket.handshake.ServerHandshake;

/**
 * US-018 cross-peer exam fixture: the REAL pinned Java-WebSocket 1.6.0
 * client run against the Rust {@code ws-testee} loopback server (or any
 * loopback peer). Scripted and deterministic: connect, optionally send one
 * ping, send one text message, expect the echo, then either close cleanly
 * (mode {@code clean}: close 1000 "done") or vanish without a close frame
 * (mode {@code halt}: {@code Runtime.halt(43)}) so the peer observes the
 * abnormal 1006 transport close.
 *
 * <p>Verification fixture only — no TLS, proxy, reconnect, or general API.
 * Every observation is printed as one {@code event=...} line on stdout; the
 * exit code is 0 only when the echo arrived and the close completed with
 * code 1000.
 */
public final class CrossPeerClient extends WebSocketClient {

    private final String message;
    private final boolean halt;
    private final byte[] ping;
    private final CountDownLatch closed = new CountDownLatch(1);
    private volatile boolean echoed;
    private volatile int closeCode = -1;

    private CrossPeerClient(URI uri, String message, boolean halt, byte[] ping) {
        super(uri);
        this.message = message;
        this.halt = halt;
        this.ping = ping;
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
        System.out.println("event=open status=" + (int) handshake.getHttpStatus());
        if (ping != null) {
            PingFrame frame = new PingFrame();
            frame.setPayload(ByteBuffer.wrap(ping));
            sendFrame(frame);
            System.out.println("event=ping-sent payload=" + hex(ping));
        }
        send(message);
    }

    @Override
    public void onMessage(String text) {
        System.out.println("event=text payload=" + text);
        if (text.equals(message)) {
            echoed = true;
            if (halt) {
                System.out.flush();
                Runtime.getRuntime().halt(43);
            }
            close(1000, "done");
        }
    }

    @Override
    public void onWebsocketPong(WebSocket connection, Framedata frame) {
        byte[] payload = new byte[frame.getPayloadData().remaining()];
        frame.getPayloadData().slice().get(payload);
        System.out.println("event=pong payload=" + hex(payload));
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        System.out.println("event=close code=" + code + " reason=" + reason + " remote=" + remote);
        closeCode = code;
        closed.countDown();
    }

    @Override
    public void onError(Exception error) {
        System.out.println("event=error class=" + error.getClass().getSimpleName());
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format("%02x", value));
        }
        return out.toString();
    }

    private static byte[] parseHex(String text) {
        if (text.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[text.length() / 2];
        for (int index = 0; index < out.length; index++) {
            out[index] = (byte) Integer.parseInt(text.substring(index * 2, index * 2 + 2), 16);
        }
        return out;
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 5) {
            System.err.println("usage: CrossPeerClient <host:port> <path> <message> <clean|halt> <ping-hex|->");
            System.exit(2);
        }
        String mode = arguments[3];
        if (!mode.equals("clean") && !mode.equals("halt")) {
            System.err.println("usage: mode must be clean or halt");
            System.exit(2);
        }
        byte[] ping = arguments[4].equals("-") ? null : parseHex(arguments[4]);
        URI uri = new URI("ws://" + arguments[0] + arguments[1]);
        CrossPeerClient client =
                new CrossPeerClient(uri, arguments[2], mode.equals("halt"), ping);
        if (!client.connectBlocking(10, TimeUnit.SECONDS)) {
            System.out.println("result=connect-failed");
            System.exit(4);
        }
        if (!client.closed.await(20, TimeUnit.SECONDS)) {
            System.out.println("result=close-timeout");
            System.exit(5);
        }
        boolean pass = client.echoed && client.closeCode == 1000;
        System.out.println(
                "result=" + (pass ? "clean" : "unclean")
                        + " echoed=" + client.echoed
                        + " close_code=" + client.closeCode);
        System.exit(pass ? 0 : 1);
    }
}
