package net.midiandmore.newserv.spamscan;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class SpamRules {
    private final Path badwordsFile;
    private final Path glineBadwordsFile;
    private final Set<String> badwords;
    private final Set<String> glineBadwords;
    private final Map<Integer, String> glyphs;

    SpamRules(JsonConfig config) throws IOException {
        badwordsFile = Path.of(config.get("badwordsFile", "badwords-spamscan.json"));
        glineBadwordsFile = Path.of(config.get("glineBadwordsFile", "badwords-gline.json"));
        badwords = loadWords(badwordsFile);
        glineBadwords = loadWords(glineBadwordsFile);
        glyphs = loadGlyphs(Path.of(config.get("charsFile", "chars.txt")));
    }

    synchronized boolean add(String word, boolean gline) throws IOException {
        String candidate = word.trim();
        if (candidate.isEmpty()) {
            return false;
        }
        Set<String> words = words(gline);
        String normalized = normalize(candidate);
        if (words.stream().anyMatch(existing -> normalize(existing).equals(normalized))) {
            return false;
        }
        Set<String> updated = new LinkedHashSet<>(words);
        updated.add(candidate);
        save(gline ? glineBadwordsFile : badwordsFile, updated);
        words.add(candidate);
        return true;
    }

    synchronized boolean remove(String word, boolean gline) throws IOException {
        String normalized = normalize(word.trim());
        if (normalized.isEmpty()) {
            return false;
        }
        Set<String> words = words(gline);
        Set<String> updated = new LinkedHashSet<>(words);
        if (!updated.removeIf(existing -> normalize(existing).equals(normalized))) {
            return false;
        }
        save(gline ? glineBadwordsFile : badwordsFile, updated);
        words.clear();
        words.addAll(updated);
        return true;
    }

    synchronized List<String> list(boolean gline) {
        return List.copyOf(words(gline));
    }

    synchronized String match(String message, boolean gline) {
        String normalized = normalize(message);
        for (String word : words(gline)) {
            String needle = normalize(word);
            if (!needle.isEmpty() && normalized.contains(needle)) {
                return word;
            }
        }
        return null;
    }

    boolean hasHomoglyphs(String message) {
        return message.codePoints().anyMatch(codePoint -> codePoint > 127
                && (glyphs.containsKey(codePoint) || !Normalizer.normalize(
                        new String(Character.toChars(codePoint)), Normalizer.Form.NFKC)
                        .equals(new String(Character.toChars(codePoint)))));
    }

    private Set<String> words(boolean gline) {
        return gline ? glineBadwords : badwords;
    }

    private static Set<String> loadWords(Path path) throws IOException {
        Set<String> words = new LinkedHashSet<>();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8);
             var json = Json.createReader(reader)) {
            JsonArray entries = json.readArray();
            for (JsonObject entry : entries.getValuesAs(JsonObject.class)) {
                String word = entry.getString("name").trim();
                if (!word.isEmpty()) {
                    words.add(word);
                }
            }
        } catch (NoSuchFileException ignored) {
            // A missing rules file starts with an empty set.
        }
        return words;
    }

    private static Map<Integer, String> loadGlyphs(Path path) throws IOException {
        Map<Integer, String> glyphs = new HashMap<>();
        try (var lines = Files.lines(path, StandardCharsets.UTF_8)) {
            lines.filter(line -> !line.isEmpty() && !line.startsWith("#"))
                    .forEach(line -> {
                        int canonical = line.codePointAt(0);
                        String replacement = new String(Character.toChars(canonical));
                        for (int offset = Character.charCount(canonical); offset < line.length();) {
                            int glyph = line.codePointAt(offset);
                            offset += Character.charCount(glyph);
                            if (!Character.isWhitespace(glyph) && glyph != canonical) {
                                glyphs.put(glyph, replacement);
                            }
                        }
                    });
        } catch (NoSuchFileException ignored) {
            // NFKC still handles compatibility characters without a mapping file.
        }
        return glyphs;
    }

    private String normalize(String text) {
        String compatibility = Normalizer.normalize(text, Normalizer.Form.NFKC);
        StringBuilder mapped = new StringBuilder(compatibility.length());
        compatibility.codePoints().forEach(codePoint -> mapped.append(glyphs.getOrDefault(
                codePoint, new String(Character.toChars(codePoint)))));
        return Normalizer.normalize(mapped, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    private static void save(Path path, Set<String> words) throws IOException {
        JsonArrayBuilder entries = Json.createArrayBuilder();
        for (String word : words) {
            entries.add(Json.createObjectBuilder().add("name", word).add("value", ""));
        }
        Path absolute = path.toAbsolutePath();
        Path temporary = Files.createTempFile(absolute.getParent(), ".spamrules-", ".tmp");
        try {
            try (Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                Json.createWriter(writer).writeArray(entries.build());
            }
            Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException ex) {
            throw new IOException("Atomic replacement is unavailable for " + path, ex);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
