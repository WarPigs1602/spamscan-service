package net.midiandmore.newserv.spamscan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

final class P10SpamScanRelay {
    private static final Logger LOG = Logger.getLogger(P10SpamScanRelay.class.getName());
    private final JsonConfig config;
    private final boolean debug;
    private final AtomicBoolean burstComplete = new AtomicBoolean(false);
    private final ConcurrentHashMap<String, NickUser> users = new ConcurrentHashMap<>();
    private final Map<String, ChannelState> channels = new HashMap<>();
    private SpamDatabase database;
    private SpamRules rules;
    private ExecutorService blacklistExecutor;
    private volatile PrintWriter writer;
    private static final String BUILD_DATE;
    static {
        String date = "unknown";
        try (InputStream in = P10SpamScanRelay.class.getClassLoader().getResourceAsStream("build.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                date = props.getProperty("build.date", date);
            }
        } catch (IOException ex) {
            LOG.log(Level.WARNING, "Could not load build.properties", ex);
        }
        BUILD_DATE = date;
    }

    private static final class ChannelState {
        private final Map<String, Long> joined = new HashMap<>();
        private final Set<String> operators = new HashSet<>();
        private final Set<String> voiced = new HashSet<>();
        private final Set<Character> modes = new HashSet<>();

        private boolean moderated() {
            return modes.contains('m');
        }
    }

    private static final class NickUser {
        private String nick;
        private String account;
        private final String host;
        private final String ip;
        private final Set<String> channels = new HashSet<>();
        private String lastLine = "";
        private int flood;
        private int repeat;
        private int spamScore;
        private int kickCount;
        private long lastScoreDecay = System.currentTimeMillis() / 1000;
        private long lastFloodDecay = lastScoreDecay;

        private NickUser(String nick, String account, String host, String ip) {
            this.nick = nick;
            this.account = account;
            this.host = host;
            this.ip = ip;
        }

        private String nick() {
            return nick;
        }

        private String account() {
            return account;
        }

        private String host() {
            return host;
        }

        private String ip() {
            return ip;
        }
    }

    P10SpamScanRelay(JsonConfig config) {
        this(config, false);
    }

    P10SpamScanRelay(JsonConfig config, boolean debug) {
        this.config = config;
        this.debug = debug;
    }

    void run() throws InterruptedException {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                connect();
            } catch (Exception ex) {
                LOG.log(Level.WARNING, "Relay disconnected", ex);
            } finally {
                writer = null;
                burstComplete.set(false);
                users.clear();
                channels.clear();
            }
            Thread.sleep(10_000);
        }
    }

    private void connect() throws Exception {
        try (Socket socket = new Socket(config.get("host", "127.0.0.1"), config.intValue("port", 4400));
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             SpamDatabase db = config.get("dbhost", "").isBlank() || config.get("db", "").isBlank()
                     ? null : new SpamDatabase(config)) {
            database = db;
            rules = new SpamRules(config);
            blacklistExecutor = Executors.newSingleThreadExecutor(task -> {
                Thread thread = new Thread(task, "spamscan-dnsbl");
                thread.setDaemon(true);
                return thread;
            });
            writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
            send("PASS :%s", config.get("password", ""));
            send("SERVER %s 2 %d %d J10 %s]]] +hs6n :%s", config.get("servername", "spamscan.midiandmore.net"), now(), now(),
                    config.get("numeric", "SZ"), config.get("description", "Spam scan relay"));
            send("%s N %s 2 %d %s %s +oikr - %s U]AEB %sAAA :%s",
                    numeric(), config.get("nick", "S"), now(), config.get("identd", "spamscan"),
                    config.get("servername", "spamscan.midiandmore.net"), config.get("account", "S"),
                    numeric(), config.get("description", "Spam scan relay"));
            send("%s EB", numeric());
            String line;
            while ((line = reader.readLine()) != null) {
                debugLine("<<", line);
                if (handlePingPong(line)) {
                    continue;
                }
                handle(line);
            }
        } finally {
            if (blacklistExecutor != null) {
                blacklistExecutor.shutdownNow();
                blacklistExecutor = null;
            }
            database = null;
            rules = null;
        }
    }

    private void handle(String line) throws SQLException {
        if (isEndOfBurst(line)) {
            if (burstComplete.compareAndSet(false, true)) {
                send("%s EA", numeric());
                if (database != null) {
                    for (String channel : database.channels()) {
                        joinChannel(channel);
                    }
                }
            }
            return;
        }
        String stripped = stripTags(line.trim());
        String[] tokens = splitIrcLine(stripped);
        if (tokens.length < 2) {
            return;
        }
        switch (tokens[1].toUpperCase(Locale.ROOT)) {
            case "N" -> handleNick(tokens);
            case "B" -> handleBurst(tokens);
            case "C" -> {
                if (tokens.length > 2) {
                    join(tokens[0], tokens[2], true, 0);
                }
            }
            case "J" -> {
                if (tokens.length > 2) {
                    join(tokens[0], tokens[2], false, now());
                }
            }
            case "AC" -> {
                if (tokens.length > 3) {
                    NickUser user = users.get(tokens[2]);
                    if (user != null) {
                        user.account = tokens[3];
                    }
                }
            }
            case "L" -> {
                if (tokens.length > 2) {
                    leave(tokens[0], tokens[2]);
                }
            }
            case "K" -> {
                if (tokens.length > 3) {
                    leave(tokens[3], tokens[2]);
                }
            }
            case "Q" -> removeUser(tokens[0]);
            case "D" -> {
                if (tokens.length > 2) {
                    removeUser(tokens[2]);
                }
            }
            case "M" -> handleModes(tokens);
            case "P", "O" -> {
                if (tokens.length > 3) {
                    if (tokens[2].equals(numeric() + "AAA") && tokens[1].equalsIgnoreCase("P")) {
                        handleCommand(tokens);
                    } else if (tokens[2].startsWith("#") || tokens[2].startsWith("&")) {
                        scanMessage(tokens);
                    }
                }
            }
            default -> {
            }
        }
    }

    private void handleBurst(String[] tokens) {
        if (tokens.length < 5) {
            return;
        }
        String channel = tokens[2].toLowerCase(Locale.ROOT);
        ChannelState state = new ChannelState();
        ChannelState previous = channels.put(channel, state);
        if (previous != null) {
            for (String member : previous.joined.keySet()) {
                NickUser oldUser = users.get(member);
                if (oldUser != null) {
                    oldUser.channels.remove(channel);
                }
            }
        }
        if (tokens.length >= 6) {
            for (char mode : tokens[4].toCharArray()) {
                if (mode != '+' && mode != '-') {
                    state.modes.add(mode);
                }
            }
        }
        String[] members = tokens[tokens.length - 1].split(",");
        for (String member : members) {
            String[] parts = member.split(":", 2);
            if (parts[0].isBlank()) {
                continue;
            }
            state.joined.put(parts[0], 0L);
            if (parts.length > 1) {
                if (parts[1].contains("o")) {
                    state.operators.add(parts[0]);
                }
                if (parts[1].contains("v")) {
                    state.voiced.add(parts[0]);
                }
            }
            NickUser user = users.get(parts[0]);
            if (user != null) {
                user.channels.add(channel);
            }
        }
    }

    private void join(String numeric, String name, boolean operator, long joinedAt) {
        String channel = name.toLowerCase(Locale.ROOT);
        ChannelState state = channels.computeIfAbsent(channel, key -> new ChannelState());
        state.joined.put(numeric, joinedAt);
        if (operator) {
            state.operators.add(numeric);
        }
        NickUser user = users.get(numeric);
        if (user != null) {
            user.channels.add(channel);
        }
    }

    private void leave(String numeric, String name) {
        String channel = name.toLowerCase(Locale.ROOT);
        ChannelState state = channels.get(channel);
        if (state != null) {
            state.joined.remove(numeric);
            state.operators.remove(numeric);
            state.voiced.remove(numeric);
            if (state.joined.isEmpty()) {
                channels.remove(channel);
            }
        }
        NickUser user = users.get(numeric);
        if (user != null) {
            user.channels.remove(channel);
        }
    }

    private void removeUser(String numeric) {
        users.remove(numeric);
        for (String channel : Set.copyOf(channels.keySet())) {
            if (channels.get(channel).joined.containsKey(numeric)) {
                leave(numeric, channel);
            }
        }
    }

    private void handleModes(String[] tokens) {
        if (tokens.length < 4) {
            return;
        }
        ChannelState channel = channels.get(tokens[2].toLowerCase(Locale.ROOT));
        if (channel == null) {
            return;
        }
        boolean add = true;
        int argument = 4;
        for (char mode : tokens[3].toCharArray()) {
            if (mode == '+') {
                add = true;
            } else if (mode == '-') {
                add = false;
            } else if (mode == 'o' || mode == 'v') {
                if (argument >= tokens.length) {
                    break;
                }
                Set<String> members = mode == 'o' ? channel.operators : channel.voiced;
                if (add) {
                    members.add(tokens[argument]);
                } else {
                    members.remove(tokens[argument]);
                }
                argument++;
            } else if (add) {
                channel.modes.add(mode);
            } else {
                channel.modes.remove(mode);
            }
        }
    }

    private void scanMessage(String[] tokens) {
        String source = tokens[0];
        String name = tokens[2].toLowerCase(Locale.ROOT);
        NickUser user = users.get(source);
        ChannelState channel = channels.get(name);
        if (!burstComplete.get() || user == null || channel == null
                || !channel.joined.containsKey(source) || rules == null) {
            return;
        }
        if (privileged(user)) {
            return;
        }

        long timestamp = now();
        decay(user, timestamp);
        long joinedAt = channel.joined.get(source);
        boolean recent = joinedAt > 0 && timestamp - joinedAt < 60;
        boolean lax = database != null && database.isLax(name);
        if (lax && (!user.account.isBlank() || joinedAt == 0 || timestamp - joinedAt >= 300)) {
            return;
        }
        int threshold = (user.account.isBlank() ? 15 : 25) + (lax ? 10 : 0);
        String message = tokens[3];
        if (joinedAt > 0 && timestamp - joinedAt < 300 && rules.hasHomoglyphs(message)) {
            user.spamScore += recent ? 10 : 5;
            if (user.spamScore >= threshold) {
                punish(source, user, name, channel, "Homoglyph spam");
            }
            return;
        }

        if (!user.lastLine.isBlank() && user.lastLine.equalsIgnoreCase(message)) {
            user.repeat++;
            user.spamScore += recent ? 5 : 2;
            if (user.spamScore >= threshold) {
                punish(source, user, name, channel, "Repeating lines");
                return;
            }
        } else {
            user.repeat = 0;
            user.lastLine = message;
        }

        user.flood++;
        user.spamScore += recent ? 3 : 1;
        if (user.spamScore >= threshold) {
            punish(source, user, name, channel, "Flooding");
            return;
        }

        String badword = rules.match(message, false);
        if (badword != null) {
            user.spamScore += recent ? 15 : 8;
            if (user.spamScore >= threshold) {
                punish(source, user, name, channel, "Badword: " + badword);
            }
            return;
        }
        String glineWord = rules.match(message, true);
        if (glineWord != null) {
            if (!user.ip.isBlank()) {
                gline("*!*@" + user.ip, 86400, "Gline badword: " + glineWord);
            }
            punish(source, user, name, channel, "Gline badword: " + glineWord);
        }
    }

    private void decay(NickUser user, long timestamp) {
        if (timestamp > user.lastScoreDecay) {
            long intervals = (timestamp - user.lastScoreDecay) / 10;
            user.spamScore = (int) Math.max(0, user.spamScore - intervals * 2);
            user.lastScoreDecay += intervals * 10;
        }
        if (timestamp > user.lastFloodDecay) {
            long intervals = (timestamp - user.lastFloodDecay) / 2;
            user.flood = (int) Math.max(0, user.flood - intervals);
            user.lastFloodDecay += intervals * 2;
        }
    }

    private void punish(String source, NickUser user, String name, ChannelState channel, String reason) {
        int id = database == null ? 0 : database.recordReason(reason);
        user.kickCount++;
        if (user.kickCount >= 2 && !user.ip.isBlank()) {
            gline("*!*" + user.host.substring(0, user.host.indexOf('@')) + "@" + user.ip,
                    600, "Repeated violation: " + reason);
            user.kickCount = 0;
        }
        if (channel.moderated() && channel.voiced.contains(source)) {
            send("%sAAA M %s -v %s", numeric(), name, source);
            channel.voiced.remove(source);
            if (id > 0 && violationLink(id) != null) {
                send("%sAAA O %s :Network rules violation, %s", numeric(), source, violationReference(id));
            }
        } else if (id > 0) {
            send("%sAAA D %s %d :Network rules violation, %s", numeric(), source, now(), violationReference(id));
        } else {
            send("%sAAA D %s %d :Network rules violation: %s", numeric(), source, now(), reason);
        }
    }

    private String violationReference(int id) {
        String reference = "ID: " + id;
        String link = violationLink(id);
        return link == null ? reference : reference + " (" + link + ")";
    }

    private String violationLink(int id) {
        String template = config.get("violationUrl", "");
        if (!template.contains("{id}")) {
            return null;
        }
        String link = template.replace("{id}", Integer.toString(id));
        try {
            URI url = URI.create(link);
            if (("https".equalsIgnoreCase(url.getScheme()) || "http".equalsIgnoreCase(url.getScheme()))
                    && url.getHost() != null && url.getUserInfo() == null) {
                return link;
            }
        } catch (IllegalArgumentException ignored) {
            // Keep the violation ID visible when the URL template is invalid.
        }
        return null;
    }

    private void gline(String mask, int seconds, String reason) {
        int configured = config.intValue("glineDuration", seconds);
        int duration = configured > 0 ? configured : seconds;
        send("%s GL * +%s %d %d :%s", numeric(), mask, duration, now(), reason);
    }

    private boolean privileged(NickUser user) {
        return database != null && !user.account.isBlank()
                && (database.flags(user.account) & (0x20 | 0x40 | 0x200)) != 0;
    }

    private void handleCommand(String[] tokens) {
        String source = tokens[0];
        NickUser user = users.get(source);
        if (!burstComplete.get() || user == null) {
            return;
        }
        String[] args = tokens[3].trim().split(" +");
        if (args.length == 0 || args[0].isBlank()) {
            return;
        }
        boolean privileged = privileged(user);
        String replyType = database != null && !user.account.isBlank()
                && (database.flags(user.account) & 0x4) != 0 ? "O" : "P";
        String command = args[0].toUpperCase(Locale.ROOT);
        if ("VERSION".equals(command)) {
            reply(source, replyType, "SpamScan service 1.0-SNAPSHOT (MidiAndMore.Net) Build: " + BUILD_DATE);
        } else if ("HELP".equals(command) && args.length == 2) {
            String usage = switch (args[1].toUpperCase(Locale.ROOT)) {
                case "ADDCHAN" -> "ADDCHAN <#channel>";
                case "BADWORD" -> "BADWORD <ADD|DELETE|LIST|GLINEADD|GLINEDELETE|GLINELIST> [word]";
                case "DELCHAN" -> "DELCHAN <#channel>";
                case "SCORE" -> "SCORE <nick>";
                default -> null;
            };
            reply(source, replyType, privileged && usage != null ? usage : "Unknown command, or access denied.");
        } else if ("HELP".equals(command) || "SHOWCOMMANDS".equals(command)) {
            reply(source, replyType, "Public commands:");
            reply(source, replyType, "HELP [command] - Show available commands or usage for a command.");
            reply(source, replyType, "SHOWCOMMANDS - List available commands with descriptions.");
            reply(source, replyType, "VERSION - Show the service version and build date/time (UTC).");
            if (privileged) {
                reply(source, replyType, "Privileged commands:");
                reply(source, replyType, "ADDCHAN <#channel> - Add a channel to spam monitoring.");
                reply(source, replyType, "DELCHAN <#channel> - Remove a channel from spam monitoring.");
                reply(source, replyType, "BADWORD <ADD|DELETE|LIST|GLINEADD|GLINEDELETE|GLINELIST> [word] - Manage spam and G-line word lists.");
                reply(source, replyType, "SCORE <nick> - Show a user's current spam score.");
            }
        } else if (("ADDCHAN".equals(command) || "DELCHAN".equals(command))
                && args.length == 2 && database != null && privileged) {
            String channel = args[1].toLowerCase(Locale.ROOT);
            if (!channel.startsWith("#") && !channel.startsWith("&")) {
                reply(source, replyType, "Invalid channel.");
            } else if ("ADDCHAN".equals(command) && channels.containsKey(channel) && !database.isChannel(channel)) {
                database.addChannel(channel);
                joinChannel(channel);
                reply(source, replyType, "Added channel " + channel);
            } else if ("DELCHAN".equals(command) && database.isChannel(channel)) {
                database.removeChannel(channel);
                send("%sAAA L %s", numeric(), channel);
                reply(source, replyType, "Removed channel " + channel);
            } else {
                reply(source, replyType, "Channel is unavailable or already configured.");
            }
        } else if ("BADWORD".equals(command) && privileged && args.length >= 2 && rules != null) {
            String action = args[1].toUpperCase(Locale.ROOT);
            boolean gline = action.startsWith("GLINE");
            if ("LIST".equals(action) || "GLINELIST".equals(action)) {
                reply(source, replyType, gline ? "Gline badwords:" : "Badwords:");
                for (String word : rules.list(gline)) {
                    reply(source, replyType, word);
                }
            } else if (("ADD".equals(action) || "DELETE".equals(action)
                    || "GLINEADD".equals(action) || "GLINEDELETE".equals(action)) && args.length >= 3) {
                String word = String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length));
                try {
                    boolean changed = action.endsWith("ADD") ? rules.add(word, gline) : rules.remove(word, gline);
                    reply(source, replyType, changed ? "Badword updated." : "Badword unchanged.");
                } catch (IOException ex) {
                    System.err.println("Could not save badwords: " + ex.getMessage());
                    reply(source, replyType, "Could not save badwords.");
                }
            } else {
                reply(source, replyType, "BADWORD <ADD|DELETE|LIST|GLINEADD|GLINEDELETE|GLINELIST> [word]");
            }
        } else if ("SCORE".equals(command) && privileged && args.length == 2) {
            for (NickUser target : users.values()) {
                if (target.nick.equalsIgnoreCase(args[1])) {
                    decay(target, now());
                    reply(source, replyType, "Spamscore for " + target.nick + ": " + target.spamScore);
                    return;
                }
            }
            reply(source, replyType, "User not found.");
        } else {
            reply(source, replyType, "Unknown command, or access denied.");
        }
    }

    private void reply(String source, String type, String message) {
        send("%sAAA %s %s :%s", numeric(), type, source, message);
    }

    private void joinChannel(String channel) {
        send("%sAAA J %s", numeric(), channel);
        send("%s M %s +o %sAAA", numeric(), channel, numeric());
    }

    private void handleNick(String[] tokens) {
        if (tokens.length == 4) {
            users.computeIfPresent(tokens[0], (numeric, user) -> {
                user.nick = tokens[2];
                return user;
            });
            return;
        }
        if (tokens.length < 10 || tokens[2].isBlank() || tokens[tokens.length - 2].isBlank()) {
            return;
        }

        String numeric = tokens[tokens.length - 2];
        String nick = tokens[2];
        String ident = tokens[5];
        String host = tokens[6];
        if (antiKnocker(nick, ident)) {
            int id = database == null ? 0 : database.recordReason("Spambot!");
            if (id > 0) {
                send("%sAAA D %s %d :Detected as Spambot, %s", numeric(), numeric, now(), violationReference(id));
            } else {
                send("%sAAA D %s %d :Detected as Spambot", numeric(), numeric, now());
            }
            return;
        }

        String account = null;
        if (tokens[7].contains("h") && tokens[7].contains("z") && tokens[7].contains("r")) {
            account = tokens.length > 10 && tokens[tokens.length - 6].contains(":")
                    ? tokens[tokens.length - 6].split(":", 2)[0] : "";
        } else if ((tokens[7].contains("h") && tokens[7].contains("r")) || (tokens[7].contains("z") && tokens[7].contains("r"))) {
            account = tokens.length > 10 && tokens[tokens.length - 5].contains(":")
                    ? tokens[tokens.length - 5].split(":", 2)[0] : "";
        } else if (tokens[7].contains("r")) {
            account = tokens.length > 10 && tokens[tokens.length - 4].contains(":")
                    ? tokens[tokens.length - 4].split(":", 2)[0] : "";
        }
        String ip = "";
        if (!tokens[7].contains("k")) {
            try {
                ip = InetAddress.getByName(host).getHostAddress();
            } catch (UnknownHostException ignored) {
                // A hostname need not resolve to a public IP address.
            }
        }
        NickUser user = new NickUser(nick, account, ident + "@" + host, ip);
        for (Map.Entry<String, ChannelState> entry : channels.entrySet()) {
            if (entry.getValue().joined.containsKey(numeric)) {
                user.channels.add(entry.getKey());
            }
        }
        users.put(numeric, user);
        if (!ip.isBlank() && blacklistExecutor != null
                && Boolean.parseBoolean(config.get("dnsbl", "true"))) {
            String address = ip;
            PrintWriter connectionWriter = writer;
            blacklistExecutor.submit(() -> checkBlacklist(address, connectionWriter));
        }
    }

    private void checkBlacklist(String ip, PrintWriter connectionWriter) {
        String reason = null;
        if (listed(ip, "dnsbl.dronebl.org")) {
            reason = "DroneBL";
        } else if (listed(ip, "dnsbl.efbl.org")) {
            reason = "EFBL";
        }
        if (reason != null && writer == connectionWriter && connectionWriter != null) {
            gline("*!*@" + ip, 86400, reason);
        }
    }

    private boolean listed(String ip, String zone) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            } catch (NumberFormatException ex) {
                return false;
            }
        }
        String query = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + "." + zone;
        try {
            byte[] result = InetAddress.getByName(query).getAddress();
            return result.length == 4 && (result[0] & 0xff) == 127;
        } catch (UnknownHostException ex) {
            return false;
        }
    }

    private boolean antiKnocker(String nick, String ident) {
        if (ident.startsWith("~")) {
            ident = ident.substring(1);
        }
        String regex = "^(st|sn|cr|pl|pr|fr|fl|qu|br|gr|sh|sk|tr|kl|wr|bl|[bcdfgklmnprstvwz])([aeiou][aeiou][bcdfgklmnprstvwz])(ed|est|er|le|ly|y|ies|iest|ian|ion|est|ing|led|inger?|[abcdfgklmnprstvwz])$";
        return !ident.equalsIgnoreCase(nick) && nick.matches(regex) && ident.matches(regex);
    }

    private String stripTags(String line) {
        if (!line.startsWith("@")) {
            return line;
        }
        int tagsEnd = line.indexOf(' ');
        return tagsEnd < 0 ? "" : line.substring(tagsEnd + 1).trim();
    }

    private String[] splitIrcLine(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inTrailing = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inTrailing) {
                current.append(c);
            } else if (c == ' ') {
                if (current.length() > 0) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
            } else if (c == ':' && current.length() == 0) {
                if (i != 0) {
                    inTrailing = true;
                }
            } else {
                current.append(c);
            }
        }

        if (current.length() > 0) {
            tokens.add(current.toString());
        }

        return tokens.toArray(new String[0]);
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
        String[] tokens = splitIrcLine(candidate);
        if (tokens.length == 0) {
            return false;
        }

        int commandIndex = ("G".equalsIgnoreCase(tokens[0]) || "PING".equalsIgnoreCase(tokens[0])) ? 0 : 1;
        if (commandIndex >= tokens.length || !("G".equalsIgnoreCase(tokens[commandIndex])
                || "PING".equalsIgnoreCase(tokens[commandIndex]))) {
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
        String[] tokens = splitIrcLine(stripTags(line.trim()));
        return tokens.length > 0 && ("EB".equalsIgnoreCase(tokens[0])
                || tokens.length > 1 && "EB".equalsIgnoreCase(tokens[1]));
    }

    private void send(String format, Object... args) {
        PrintWriter output = writer;
        if (output != null) {
            String line = format.formatted(args);
            debugLine(">>", line);
            output.println(line);
        }
    }

    private void debugLine(String direction, String line) {
        if (debug) {
            System.out.println(direction + " " + redact(line));
        }
    }

    static String redact(String line) {
        String upper = line.toUpperCase(Locale.ROOT);
        if (upper.startsWith("PASS ")) {
            return "PASS <redacted>";
        }
        int password = upper.indexOf(" PASS ");
        if (password >= 0) {
            return line.substring(0, password) + " PASS <redacted>";
        }
        int auth = upper.indexOf(":AUTH ");
        if (auth < 0) {
            auth = upper.indexOf(" AUTH ");
        }
        return auth < 0 ? line : line.substring(0, auth) + line.substring(auth, auth + 5) + " <redacted>";
    }

    private String numeric() {
        return config.get("numeric", "SZ");
    }

    private long now() {
        return System.currentTimeMillis() / 1000;
    }
}
