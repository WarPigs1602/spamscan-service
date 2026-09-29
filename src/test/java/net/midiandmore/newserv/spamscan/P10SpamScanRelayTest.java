package net.midiandmore.newserv.spamscan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class P10SpamScanRelayTest {
    @Test
    void parsesDebugAndDaemonOptionsInEitherOrder() {
        Main.Options options = Main.parseArgs(new String[] {"--debug", "config.json", "--deamon"});
        assertTrue(options.debug());
        assertTrue(options.daemon());
        assertEquals(Path.of("config.json"), options.config());
        assertTrue(Main.daemonCommand(options).contains("--daemon-child"));
        assertTrue(Main.daemonCommand(options).contains("--debug"));
        assertTrue(Main.parseArgs(new String[] {"--daemon"}).daemon());
        assertThrows(IllegalArgumentException.class, () -> Main.parseArgs(new String[] {"--unknown"}));
        assertThrows(IllegalArgumentException.class, () -> Main.parseArgs(new String[] {"--deamon", "--daemon-child"}));
    }

    @Test
    void hidesCredentialsInDebugOutput() {
        assertEquals("PASS <redacted>", P10SpamScanRelay.redact("PASS :secret"));
        assertEquals("AAAAB P SZAAA :AUTH <redacted>",
                P10SpamScanRelay.redact("AAAAB P SZAAA :AUTH user secret"));
        assertEquals("AAAAB P #room :normal text", P10SpamScanRelay.redact("AAAAB P #room :normal text"));
    }

    @Test
    void daemonDoesNotStartWithMissingConfig(@TempDir Path directory) {
        assertThrows(NoSuchFileException.class,
                () -> Main.main(new String[] {"--deamon", directory.resolve("missing.json").toString()}));
    }

    @Test
    void debugMasksPasswordButStillSendsIt() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config(), true);
        StringWriter network = new StringWriter();
        Field writer = P10SpamScanRelay.class.getDeclaredField("writer");
        writer.setAccessible(true);
        writer.set(relay, new PrintWriter(network, true));
        Method send = P10SpamScanRelay.class.getDeclaredMethod("send", String.class, Object[].class);
        send.setAccessible(true);
        ByteArrayOutputStream console = new ByteArrayOutputStream();
        PrintStream original = System.out;
        try (PrintStream capture = new PrintStream(console, true, StandardCharsets.UTF_8)) {
            System.setOut(capture);
            send.invoke(relay, "PASS :%s", (Object) new Object[] {"secret"});
        } finally {
            System.setOut(original);
        }

        assertTrue(console.toString(StandardCharsets.UTF_8).contains(">> PASS <redacted>"));
        assertFalse(console.toString(StandardCharsets.UTF_8).contains("secret"));
        assertTrue(network.toString().contains("PASS :secret"));
    }

    @Test
    void registersUserDuringBurstAndUpdatesNickByNumeric() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config());
        receive(relay, "AA N alice 1 123 id 127.0.0.1 +i account:0 0 AAAAB :Real Name");

        Object user = users(relay).get("AAAAB");
        assertEquals("alice", value(user, "nick"));
        assertEquals("account", value(user, "account"));
        assertEquals("id@127.0.0.1", value(user, "host"));
        assertEquals("127.0.0.1", value(user, "ip"));

        receive(relay, "AAAAB N alice2 456");
        assertEquals(1, users(relay).size());
        assertEquals("alice2", value(users(relay).get("AAAAB"), "nick"));
    }

    @Test
    void rejectsAntiKnockerWithoutRegisteringUser() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config());
        StringWriter output = new StringWriter();
        Field writer = P10SpamScanRelay.class.getDeclaredField("writer");
        writer.setAccessible(true);
        writer.set(relay, new PrintWriter(output, true));

        receive(relay, "AA N staaded 1 123 snaaded 127.0.0.1 +i - 0 AAAAB :Bot");

        assertFalse(users(relay).containsKey("AAAAB"));
        assertTrue(output.toString().contains(" D AAAAB "));
    }

    @Test
    void tracksChannelsAndDevoicesRepeatedSpam(@TempDir Path directory) throws Exception {
        JsonConfig config = config(Map.of(
                "badwordsFile", directory.resolve("words.json").toString(),
                "glineBadwordsFile", directory.resolve("glines.json").toString()));
        P10SpamScanRelay relay = new P10SpamScanRelay(config);
        Field rules = P10SpamScanRelay.class.getDeclaredField("rules");
        rules.setAccessible(true);
        rules.set(relay, new SpamRules(config));
        StringWriter output = new StringWriter();
        Field writer = P10SpamScanRelay.class.getDeclaredField("writer");
        writer.setAccessible(true);
        writer.set(relay, new PrintWriter(output, true));

        receive(relay, "AA N alice 1 123 id 127.0.0.1 +i - 0 AAAAB :Real Name");
        receive(relay, "AAAAB J #room");
        receive(relay, "AA M #room +mv AAAAB");
        Field burst = P10SpamScanRelay.class.getDeclaredField("burstComplete");
        burst.setAccessible(true);
        ((AtomicBoolean) burst.get(relay)).set(true);
        receive(relay, "AAAAB P #room :hello world");
        receive(relay, "AAAAB P #room :hello world");
        receive(relay, "AAAAB P #room :hello world");

        assertTrue(output.toString().contains(" M #room -v AAAAB"));
        assertEquals(1, users(relay).size());
        receive(relay, "AAAAB Q :Quit");
        assertTrue(users(relay).isEmpty());
    }

    @Test
    void distinguishesPingFromMessageText() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config());
        StringWriter output = new StringWriter();
        Field writer = P10SpamScanRelay.class.getDeclaredField("writer");
        writer.setAccessible(true);
        writer.set(relay, new PrintWriter(output, true));
        Method ping = P10SpamScanRelay.class.getDeclaredMethod("handlePingPong", String.class);
        ping.setAccessible(true);

        assertFalse((boolean) ping.invoke(relay, "AAAAB P #room :G SS some text"));
        assertTrue((boolean) ping.invoke(relay, "AA G SS :hello world"));
        assertTrue(output.toString().contains(" Z SS :hello world"));
    }

    @Test
    void burstMembershipAndQuitKeepOtherUsers() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config());
        receive(relay, "AA B #room 1 +m :AAAAB:o,AAAAC:v");
        receive(relay, "AA N alice 1 123 id 127.0.0.1 +i - 0 AAAAB :Alice");
        receive(relay, "AA N bob 1 123 id 127.0.0.1 +i - 0 AAAAC :Bob");
        receive(relay, "AA AC AAAAC registered");
        receive(relay, "AAAAB Q :Goodbye");

        assertFalse(users(relay).containsKey("AAAAB"));
        assertTrue(users(relay).containsKey("AAAAC"));
        assertEquals("registered", value(users(relay).get("AAAAC"), "account"));
        Field channels = P10SpamScanRelay.class.getDeclaredField("channels");
        channels.setAccessible(true);
        assertTrue(((Map<?, ?>) channels.get(relay)).containsKey("#room"));
        receive(relay, "AA K #room AAAAC :Removed");
        assertFalse(((Map<?, ?>) channels.get(relay)).containsKey("#room"));
        assertTrue(users(relay).containsKey("AAAAC"));
    }

    @Test
    void recognizesTaggedEndOfBurst() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config());
        Method end = P10SpamScanRelay.class.getDeclaredMethod("isEndOfBurst", String.class);
        end.setAccessible(true);
        assertTrue((boolean) end.invoke(relay, "@time=123 :AA EB"));
        assertFalse((boolean) end.invoke(relay, "AAAAB P #room :EB is text"));
    }

    @Test
    void loadsAndPersistsBadwords(@TempDir Path directory) throws Exception {
        JsonConfig config = config(Map.of(
                "badwordsFile", directory.resolve("words.json").toString(),
                "glineBadwordsFile", directory.resolve("glines.json").toString()));
        SpamRules rules = new SpamRules(config);
        assertFalse(rules.hasHomoglyphs("normal text"));
        assertTrue(rules.hasHomoglyphs("ｆullwidth"));
        assertTrue(rules.add("Spam Word", false));
        assertNotNull(new SpamRules(config).match("SPAM WORD here", false));
        assertTrue(rules.remove("spam word", false));
        assertEquals(null, new SpamRules(config).match("spam word", false));
    }

    @Test
    void glinesConfiguredWordsAndRejectsUnauthorizedCommands(@TempDir Path directory) throws Exception {
        JsonConfig config = config(Map.of(
                "badwordsFile", directory.resolve("words.json").toString(),
                "glineBadwordsFile", directory.resolve("glines.json").toString(),
                "glineDuration", "3600",
                "violationUrl", "https://example.org/violations/{id}"));
        P10SpamScanRelay relay = new P10SpamScanRelay(config);
        SpamRules scanner = new SpamRules(config);
        scanner.add("scam", true);
        Field rules = P10SpamScanRelay.class.getDeclaredField("rules");
        rules.setAccessible(true);
        rules.set(relay, scanner);
        StringWriter output = new StringWriter();
        Field writer = P10SpamScanRelay.class.getDeclaredField("writer");
        writer.setAccessible(true);
        writer.set(relay, new PrintWriter(output, true));
        receive(relay, "AA N alice 1 123 id 127.0.0.1 +i - 0 AAAAB :Alice");
        receive(relay, "AAAAB J #room");
        Field burst = P10SpamScanRelay.class.getDeclaredField("burstComplete");
        burst.setAccessible(true);
        ((AtomicBoolean) burst.get(relay)).set(true);

        receive(relay, "AAAAB P #room :this is a SCAM");
        receive(relay, "AAAAB P SZAAA :BADWORD ADD another");

        assertTrue(output.toString().contains(" GL * +*!*@127.0.0.1 3600 "));
        assertTrue(output.toString().contains(" D AAAAB "));
        assertFalse(output.toString().contains("https://example.org/violations/"));
        assertTrue(output.toString().contains("Unknown command, or access denied."));
        assertEquals(null, scanner.match("another", false));
    }

    @Test
    void nonPositiveGlineDurationFallsBackToOriginalDuration() throws Exception {
        P10SpamScanRelay relay = new P10SpamScanRelay(config(Map.of("glineDuration", "0")));
        StringWriter output = new StringWriter();
        Field writer = P10SpamScanRelay.class.getDeclaredField("writer");
        writer.setAccessible(true);
        writer.set(relay, new PrintWriter(output, true));
        Method gline = P10SpamScanRelay.class.getDeclaredMethod("gline", String.class, int.class, String.class);
        gline.setAccessible(true);

        gline.invoke(relay, "*!*@127.0.0.1", 600, "Repeated violation");

        assertTrue(output.toString().contains(" GL * +*!*@127.0.0.1 600 "));
    }

    @Test
    void violationLinkUsesDatabaseIdAndFallsBackForInvalidTemplates() throws Exception {
        Method reference = P10SpamScanRelay.class.getDeclaredMethod("violationReference", int.class);
        reference.setAccessible(true);
        P10SpamScanRelay configured = new P10SpamScanRelay(config(Map.of(
                "violationUrl", "https://example.org/violations/{id}?from=irc")));

        assertEquals("ID: 42 (https://example.org/violations/42?from=irc)",
                reference.invoke(configured, 42));
        assertEquals("ID: 42", reference.invoke(new P10SpamScanRelay(config()), 42));
        assertEquals("ID: 42", reference.invoke(new P10SpamScanRelay(config(Map.of(
                "violationUrl", "javascript:alert({id})"))), 42));
        assertEquals("ID: 42", reference.invoke(new P10SpamScanRelay(config(Map.of(
                "violationUrl", "https://example.org/violations/"))), 42));
    }

    private void receive(P10SpamScanRelay relay, String line) throws Exception {
        Method handle = P10SpamScanRelay.class.getDeclaredMethod("handle", String.class);
        handle.setAccessible(true);
        handle.invoke(relay, line);
    }

    private JsonConfig config() throws Exception {
        return config(Map.of());
    }

    private JsonConfig config(Map<String, String> values) throws Exception {
        Constructor<JsonConfig> constructor = JsonConfig.class.getDeclaredConstructor(Map.class);
        constructor.setAccessible(true);
        return constructor.newInstance(values);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> users(P10SpamScanRelay relay) throws Exception {
        Field users = P10SpamScanRelay.class.getDeclaredField("users");
        users.setAccessible(true);
        return (Map<String, Object>) users.get(relay);
    }

    private String value(Object user, String property) throws Exception {
        Method accessor = user.getClass().getDeclaredMethod(property);
        accessor.setAccessible(true);
        return (String) accessor.invoke(user);
    }
}
