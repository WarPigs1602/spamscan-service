package net.midiandmore.newserv.spamscan;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

final class SpamDatabase implements AutoCloseable {
    private final Connection connection;

    SpamDatabase(JsonConfig config) throws SQLException {
        Properties properties = new Properties();
        properties.setProperty("user", config.get("dbuser", ""));
        properties.setProperty("password", config.get("dbpassword", ""));
        properties.setProperty("ssl", config.get("dbssl", "false"));
        String url = "jdbc:postgresql://" + config.get("dbhost", "localhost") + "/" + config.get("db", "spamscan");
        Connection opened = DriverManager.getConnection(url, properties);
        try {
            try (Statement statement = opened.createStatement()) {
                statement.executeUpdate("CREATE SCHEMA IF NOT EXISTS spamscan");
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS spamscan.channels ("
                        + "id SERIAL PRIMARY KEY, channel VARCHAR(255), lax BOOLEAN DEFAULT FALSE)");
                statement.executeUpdate("ALTER TABLE spamscan.channels ADD COLUMN IF NOT EXISTS lax BOOLEAN DEFAULT FALSE");
                statement.executeUpdate("CREATE TABLE IF NOT EXISTS spamscan.id ("
                        + "id SERIAL PRIMARY KEY, reason VARCHAR(255))");
            }
        } catch (SQLException ex) {
            try {
                opened.close();
            } catch (SQLException closeEx) {
                ex.addSuppressed(closeEx);
            }
            throw ex;
        }
        connection = opened;
    }

    List<String> channels() throws SQLException {
        List<String> channels = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("SELECT channel FROM spamscan.channels");
             ResultSet results = statement.executeQuery()) {
            while (results.next()) {
                channels.add(results.getString("channel"));
            }
        }
        return channels;
    }

    boolean isChannel(String channel) {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM spamscan.channels WHERE channel = ?")) {
            statement.setString(1, channel);
            try (ResultSet results = statement.executeQuery()) {
                return results.next();
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to check channel", ex);
        }
    }

    boolean isLax(String channel) {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT lax FROM spamscan.channels WHERE channel = ?")) {
            statement.setString(1, channel);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() && results.getBoolean("lax");
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to check channel lax setting", ex);
        }
    }

    void addChannel(String channel) {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO spamscan.channels (channel) VALUES (?)")) {
            statement.setString(1, channel);
            statement.executeUpdate();
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to add channel", ex);
        }
    }

    void removeChannel(String channel) {
        try (PreparedStatement statement = connection.prepareStatement(
                "DELETE FROM spamscan.channels WHERE channel = ?")) {
            statement.setString(1, channel);
            statement.executeUpdate();
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to remove channel", ex);
        }
    }

    int flags(String account) {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT flags FROM chanserv.users WHERE username = ?")) {
            statement.setString(1, account);
            try (ResultSet results = statement.executeQuery()) {
                return results.next() ? results.getInt("flags") : 0;
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to look up account flags", ex);
        }
    }

    int recordReason(String reason) {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO spamscan.id (reason) VALUES (?) RETURNING id")) {
            statement.setString(1, reason);
            try (ResultSet results = statement.executeQuery()) {
                if (results.next()) {
                    return results.getInt("id");
                }
                throw new IllegalStateException("Reason insert did not return an ID");
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to record reason", ex);
        }
    }

    @Override
    public void close() throws SQLException {
        connection.close();
    }
}
