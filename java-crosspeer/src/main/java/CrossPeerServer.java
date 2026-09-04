import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.java_websocket.WebSocket;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

/**
 * US-018 cross-peer exam fixture: the REAL pinned Java-WebSocket 1.6.0
 * server accepting exactly one Rust {@code ws-testee} loopback client.
 * Echoes every text/binary message and keeps the library's own default
 * control behavior — the shipped {@code WebSocketAdapter.onWebsocketPing}
 * auto-pong runs unchanged (it is only logged here before delegating), so
 * the exam observes genuine shipped-Java control responses on the wire.
 *
 * <p>Verification fixture only — loopback bind, one connection, no TLS,
 * proxy, or general API. Prints {@code listening <port>} once started and
 * one {@code event=...} line per observation; exits 0 only when an echo was
 * served and the close handshake completed with code 1000.
 */
public final class CrossPeerServer extends WebSocketServer {

    private final CountDownLatch closed = new CountDownLatch(1);
    private final CountDownLatch started = new CountDownLatch(1);
    private volatile boolean echoServed;
    private volatile int closeCode = -1;

    private CrossPeerServer(InetSocketAddress address) {
        super(address);
        setReuseAddr(true);
    }

    @Override
    public void onStart() {
        System.out.println("listening " + getPort());
        started.countDown();
    }

    @Override
    public void onOpen(WebSocket connection, ClientHandshake handshake) {
        System.out.println("event=open resource=" + handshake.getResourceDescriptor());
    }

    @Override
    public void onMessage(WebSocket connection, String text) {
        System.out.println("event=text payload=" + text);
        connection.send(text);
        echoServed = true;
    }

    @Override
    public void onWebsocketPing(WebSocket connection, Framedata frame) {
        byte[] payload = new byte[frame.getPayloadData().remaining()];
        frame.getPayloadData().slice().get(payload);
        System.out.println("event=ping payload=" + hex(payload));
        // Delegate to the shipped default: the library's own auto-pong.
        super.onWebsocketPing(connection, frame);
    }

    @Override
    public void onClose(WebSocket connection, int code, String reason, boolean remote) {
        System.out.println("event=close code=" + code + " reason=" + reason + " remote=" + remote);
        closeCode = code;
        closed.countDown();
    }

    @Override
    public void onError(WebSocket connection, Exception error) {
        System.out.println("event=error class=" + error.getClass().getSimpleName());
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format("%02x", value));
        }
        return out.toString();
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) {
            System.err.println("usage: CrossPeerServer <port|0>");
            System.exit(2);
        }
        int port = Integer.parseInt(arguments[0]);
        CrossPeerServer server = new CrossPeerServer(new InetSocketAddress("127.0.0.1", port));
        server.start();
        if (!server.started.await(10, TimeUnit.SECONDS)) {
            System.out.println("result=start-timeout");
            System.exit(4);
        }
        boolean sawClose = server.closed.await(30, TimeUnit.SECONDS);
        server.stop(1000);
        boolean pass = sawClose && server.echoServed && server.closeCode == 1000;
        System.out.println(
                "result=" + (pass ? "clean" : "unclean")
                        + " echo_served=" + server.echoServed
                        + " close_code=" + server.closeCode);
        System.exit(pass ? 0 : 1);
    }
}
