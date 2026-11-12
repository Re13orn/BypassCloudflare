package dev.burp.cfbypass;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.function.Consumer;

/**
 * Manages the embedded cfproxy process so the user never has to open a
 * terminal. On extension load it health-checks the proxy, starts the embedded
 * binary if nothing is listening, and forwards its logs to the suite tab.
 * The listen port is configurable; if it is taken by another process, a free
 * port is chosen automatically and reported via the port listener.
 * Independent of the Montoya API so it can be tested standalone.
 */
public class ProxyManager {

    private static final String HOST = "127.0.0.1";

    private final Consumer<String> logger;
    private volatile int port;
    private Consumer<Integer> portListener;
    private Process process;

    public ProxyManager(int port, Consumer<String> logger) {
        this.port = port;
        this.logger = logger;
    }

    public int getPort() {
        return port;
    }

    /** Called when the effective port changes (manual set or auto-reassign). */
    public void setPortListener(Consumer<Integer> listener) {
        this.portListener = listener;
    }

    public synchronized void setPort(int port) {
        this.port = port;
    }

    /** True only if a cfproxy (not some other process) answers on the port. */
    public boolean isRunning() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(HOST, port), 1500);
            s.setSoTimeout(2000);
            OutputStream out = s.getOutputStream();
            out.write(("GET http://cfproxy/status HTTP/1.1\r\n"
                    + "Host: cfproxy\r\nConnection: close\r\n\r\n").getBytes());
            out.flush();
            // Read raw bytes: the status body has no trailing newline and the
            // connection is keep-alive, so readLine() would block forever.
            InputStream in = s.getInputStream();
            StringBuilder sb = new StringBuilder();
            byte[] tmp = new byte[4096];
            long deadline = System.currentTimeMillis() + 2500;
            while (System.currentTimeMillis() < deadline) {
                int n = in.read(tmp);
                if (n < 0) {
                    break;
                }
                sb.append(new String(tmp, 0, n));
                if (sb.toString().contains("\"status\":\"ok\"")) {
                    return true;
                }
                if (sb.length() > 8192) {
                    break;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    /** Start the embedded binary if no cfproxy is already running. */
    public synchronized void start() {
        if (isRunning()) {
            logger.accept("cfproxy already running on " + HOST + ":" + port);
            return;
        }
        if (!isPortFree(port)) {
            int free = findFreePort(port);
            if (free < 0) {
                logger.accept("port " + port + " is busy and no free port found nearby");
                return;
            }
            logger.accept("port " + port + " is busy; using " + free
                    + " instead - set Burp upstream proxy port to " + free);
            adoptPort(free);
        }
        try {
            Path dir = Paths.get(System.getProperty("user.home"), ".cfproxy");
            Files.createDirectories(dir);
            String resource = resourceForPlatform();
            Path bin = dir.resolve(isWindows() ? "cfproxy.exe" : "cfproxy");
            try (InputStream in = getClass().getResourceAsStream(resource)) {
                if (in == null) {
                    logger.accept("no embedded cfproxy for this platform (" + resource
                            + "); run ./cfproxy manually");
                    return;
                }
                Files.copy(in, bin, StandardCopyOption.REPLACE_EXISTING);
            }
            if (!bin.toFile().setExecutable(true)) {
                logger.accept("warning: could not mark cfproxy executable");
            }

            ProcessBuilder pb = new ProcessBuilder(bin.toString(), "-listen", HOST + ":" + port);
            pb.directory(dir.toFile()); // data/ca.crt lives here
            pb.redirectErrorStream(true);
            process = pb.start();

            Thread t = new Thread(() -> pumpLogs(process.getInputStream()), "cfproxy-logs");
            t.setDaemon(true);
            t.start();
            logger.accept("cfproxy started (pid " + process.pid() + ") listening on " + HOST + ":" + port);
        } catch (IOException e) {
            logger.accept("failed to start cfproxy: " + e.getMessage());
        }
    }

    /** Stop only the process we started (a user-run cfproxy is left alone). */
    public synchronized void stop() {
        if (process != null && process.isAlive()) {
            process.destroy();
            // wait for the OS to release the listen port before a restart,
            // otherwise the next start sees the port busy and keeps incrementing.
            try {
                process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            logger.accept("cfproxy stopped");
        }
        process = null;
    }

    public synchronized void restart() {
        stop();
        start();
    }

    private void adoptPort(int newPort) {
        this.port = newPort;
        if (portListener != null) {
            portListener.accept(newPort);
        }
    }

    private boolean isPortFree(int p) {
        try (ServerSocket ss = new ServerSocket()) {
            ss.setReuseAddress(false);
            ss.bind(new InetSocketAddress(HOST, p));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private int findFreePort(int start) {
        for (int p = start + 1; p <= start + 100 && p <= 65535; p++) {
            if (isPortFree(p)) {
                return p;
            }
        }
        return -1;
    }

    private void pumpLogs(InputStream in) {
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(in))) {
            String line;
            while ((line = r.readLine()) != null) {
                logger.accept(line);
            }
        } catch (IOException ignored) {
            // stream closed on shutdown
        }
    }

    private String resourceForPlatform() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        String a = (arch.equals("aarch64") || arch.equals("arm64")) ? "arm64" : "amd64";
        if (os.contains("mac") || os.contains("darwin")) {
            return "/bin/cfproxy-darwin-" + a;
        }
        if (os.contains("linux")) {
            return "/bin/cfproxy-linux-" + a;
        }
        if (os.contains("win")) {
            return "/bin/cfproxy-windows-" + a + ".exe";
        }
        return "/bin/cfproxy-unknown";
    }

    private boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }
}
