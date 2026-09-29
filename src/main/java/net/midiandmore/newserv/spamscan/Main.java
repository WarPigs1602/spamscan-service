package net.midiandmore.newserv.spamscan;

import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        Path config = Path.of(args.length == 0 ? "config.json" : args[0]);
        new P10SpamScanRelay(JsonConfig.load(config)).run();
    }
}
