package net.midiandmore.newserv.spamscan;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

final class P10SpamScanRelay {
    private final JsonConfig config;
    private final AtomicBoolean burstComplete = new AtomicBoolean(false);
    private PrintWriter writer;

    P10SpamScanRelay(JsonConfig config) {
        this.config = config;
    }

    void run() throws InterruptedException {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                connect();
            } catch (Exception ex) {
                System.err.println("Relay disconnected: " + ex.getMessage());
            } finally {
                writer = null;
                burstComplete.set(false);
            }
            Thread.sleep(10_000);
        }
    }

    private void connect() throws Exception {
        try (Socket socket = new Socket(config.get("host", "127.0.0.1"), config.intValue("port", 4400));
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
            writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
            send("PASS :%s", config.get("password", ""));
            send("SERVER %s 2 %d %d J10 %s]]] +hs6n :%s", config.get("servername", "spamscan.midiandmore.net"), now(), now(),
                    config.get("numeric", "SZ"), config.get("description", "Spam scan relay"));
            send("%s N %s 2 %d %s %s +oikr - %s:%s:%s U]AEB %sAAA :%s",
                    numeric(), config.get("nick", "S"), now(), config.get("identd", "spamscan"),
                    config.get("servername", "spamscan.midiandmore.net"), config.get("account", "S"), now(), config.get("id", "777"),
                    numeric(), config.get("description", "Spam scan relay"));
            send("%s EB", numeric());
            String line;
            while ((line = reader.readLine()) != null) {
                if (handlePingPong(line)) {
                    continue;
                }
                if (isEndOfBurst(line)) {
                    burstComplete.set(true);
                    send("%s EA", numeric());
                    continue;
                }
                handle(line);
            }
        }
    }

    private void handle(String line) {
        if (!burstComplete.get()) {
            return;
        }
        String stripped = stripTags(line.trim());
        System.err.println("Received: " + stripped);
    }

    private String stripTags(String line) {
        if (!line.startsWith("@")) {
            return line;
        }
        int tagsEnd = line.indexOf(' ');
        return tagsEnd < 0 ? "" : line.substring(tagsEnd + 1).trim();
    }

    private boolean handlePingPong(String line) {
        String candidate = stripTags(line.trim());
        if (candidate.isEmpty()) {
            return false;
        }
        if (candidate.startsWith(":")) {
            int prefixEnd = candidate.indexOf(' ');
            if (prefixEnd >= 0) {
                candidate = candidate.substring(prefixEnd + 1).trim();
            }
        }
        String[] tokens = candidate.split(" ");
        if (tokens.length == 0) {
            return false;
        }

        int commandIndex = -1;
        for (int index = 0; index < tokens.length; index++) {
            if ("G".equalsIgnoreCase(tokens[index]) || "PING".equalsIgnoreCase(tokens[index])) {
                commandIndex = index;
                break;
            }
        }
        if (commandIndex < 0) {
            return false;
        }

        String target = commandIndex + 1 < tokens.length ? tokens[commandIndex + 1] : config.get("servername", "spamscan");
        String payload = commandIndex + 2 < tokens.length ? tokens[commandIndex + 2] : target;
        if (target.startsWith(":")) {
            target = target.substring(1);
        }
        if (payload.startsWith(":")) {
            payload = payload.substring(1);
        }
        if (target.isBlank()) {
            target = config.get("servername", "spamscan");
        }
        if (payload.isBlank()) {
            payload = target;
        }

        send("%s Z %s :%s", numeric(), target, payload);
        return true;
    }

    private boolean isEndOfBurst(String line) {
        String[] tokens = line.split(" ");
        return tokens.length >= 2 && "EB".equalsIgnoreCase(tokens[1]);
    }

    private void send(String format, Object... args) {
        if (writer != null) {
            writer.println(format.formatted(args));
        }
    }

    private String numeric() {
        return config.get("numeric", "SZ");
    }

    private long now() {
        return System.currentTimeMillis() / 1000;
    }
}
