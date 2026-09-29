package net.midiandmore.newserv.spamscan;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public final class Main {
    record Options(Path config, boolean debug, boolean daemon, boolean child) {
    }

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        Options options = parseArgs(args);
        if (options.daemon()) {
            JsonConfig.load(options.config());
            startDaemon(options);
            return;
        }

        Logger log = Logger.getLogger(P10SpamScanRelay.class.getName());
        FileHandler errors = null;
        try {
            errors = new FileHandler("error.log", true);
            errors.setEncoding("UTF-8");
            errors.setFormatter(new SimpleFormatter());
            log.addHandler(errors);
        } catch (IOException | SecurityException ex) {
            if (errors != null) {
                errors.close();
                errors = null;
            }
            System.err.println("Could not open error.log: " + ex.getMessage());
        }
        try {
            new P10SpamScanRelay(JsonConfig.load(options.config()), options.debug()).run();
        } finally {
            if (errors != null) {
                log.removeHandler(errors);
                errors.close();
            }
        }
    }

    static Options parseArgs(String[] args) {
        Path config = Path.of("config.json");
        boolean configProvided = false;
        boolean debug = false;
        boolean daemon = false;
        boolean child = false;
        for (String arg : args) {
            switch (arg) {
                case "--debug" -> debug = true;
                case "--deamon", "--daemon" -> daemon = true;
                case "--daemon-child" -> child = true;
                default -> {
                    if (arg.startsWith("--") || configProvided) {
                        throw new IllegalArgumentException("Unknown or duplicate argument: " + arg);
                    }
                    config = Path.of(arg);
                    configProvided = true;
                }
            }
        }
        if (daemon && child) {
            throw new IllegalArgumentException("Daemon child cannot start another daemon");
        }
        return new Options(config, debug, daemon, child);
    }

    static List<String> daemonCommand(Options options) {
        String executable = System.getProperty("os.name").startsWith("Windows") ? "javaw.exe" : "java";
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", executable).toString(),
                "-cp", System.getProperty("java.class.path"), Main.class.getName(), "--daemon-child"));
        if (options.debug()) {
            command.add("--debug");
        }
        command.add(options.config().toAbsolutePath().normalize().toString());
        return command;
    }

    private static void startDaemon(Options options) throws IOException {
        ProcessBuilder child = new ProcessBuilder(daemonCommand(options));
        child.redirectInput(ProcessBuilder.Redirect.DISCARD);
        child.redirectOutput(ProcessBuilder.Redirect.appendTo(Path.of("daemon.log").toFile()));
        child.redirectErrorStream(true);
        Process process = child.start();
        System.out.println("Daemon started (PID " + process.pid() + ")");
    }
}
