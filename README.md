# spamscan-service

Standalone P10 spam scanner for newserv. It connects to an IRC network as a server, tracks users and channels, and reacts to spam with devoice, disconnect, or temporary G-lines.

## Overview

The relay introduces a service user, processes P10 network events and channel messages, and exposes private commands to that user. It supports Unicode homoglyph checks, configurable badword lists, and asynchronous DroneBL/EFBL checks. PostgreSQL is optional for persistent channel subscriptions, violation IDs, and ChanServ-based operator permissions.

On connection it sends `PASS`, `SERVER`, its service-user `N`, and `EB`. Incoming `EB` is acknowledged with `EA`, then saved channels are joined if a database is configured. User and channel state is built even during the network burst; message scanning and private commands begin only after the burst. A disconnect clears this in-memory state and triggers a reconnect after 10 seconds.

## Build

Requires Java 17 or newer and Maven. Run the commands from the repository root:

### Windows

```powershell
mvn clean package
```

### Linux

```bash
mvn clean package
```

The runnable JAR includes its dependencies:

```text
target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Run

Start the service from the repository root so that relative rule paths resolve correctly. The config argument is optional and defaults to `config.json`:

```text
java -jar target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar config.json
java -jar target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar --debug config.json
java -jar target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar --deamon config.json
java -jar target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar --deamon --debug config.json
```

`--debug` prints incoming (`<<`) and outgoing (`>>`) P10 lines. `PASS` and `AUTH` arguments are masked, but other network traffic, including message text and host information, can appear in logs. Keep debug logs private.

`--deamon` starts a separate background Java process and prints its PID. The conventional spelling `--daemon` is also accepted. The child writes console output to `daemon.log`, while connection failures are also appended to `error.log`. The launcher validates that the config can be read, but its PID message does not guarantee that the child subsequently connected successfully; check the logs. This is a background launch, not a service-manager installation or a built-in stop command. The config path and flags can appear in any order; an unknown flag or a second config path is rejected.

## Configuration

`config.json` is a JSON array of string-valued name/value entries, not a single JSON object. For example:

```json
[
  {"name":"host","value":"127.0.0.1"},
  {"name":"port","value":"4400"},
  {"name":"dnsbl","value":"false"}
]
```

File paths below are relative to the process working directory unless absolute paths are supplied. `config.json` contains example connection values: replace the placeholder `password` and configure your own server details before connecting to a network. Do not publish real passwords in the tracked sample config.

| Key | Sample or default | Purpose |
| --- | --- | --- |
| `host`, `port` | `127.0.0.1`, `4400` | IRC server address and TCP port. |
| `password` | Example value `password` | P10 server-link password; configure the real value privately. |
| `servername`, `description` | `spamscan.midiandmore.net`, `Spam scan relay` | Server identity and description sent during registration. |
| `numeric`, `nick`, `identd`, `account` | `SS`, `S`, `spamscan`, `S` | Service server numeric and user registration fields. The sample numeric differs from the code fallback `SZ`. |
| `dbhost`, `db` | Empty | PostgreSQL server (optional `:port`) and database name. Both must be nonempty to enable DB access. |
| `dbuser`, `dbpassword`, `dbssl` | Empty, empty, `false` | PostgreSQL credentials and JDBC SSL setting; only used if DB access is enabled. |
| `authuser`, `authpassword` | Empty | Optional credentials for the privileged private `AUTH` command; an empty `authuser` disables it. |
| `badwordsFile`, `glineBadwordsFile` | `badwords-spamscan.json`, `badwords-gline.json` | Ordinary and immediate-G-line word-list files. |
| `charsFile` | `chars.txt` | UTF-8 homoglyph mapping file; included in this repository. |
| `dnsbl` | `true` | Submit visible, resolved IPv4 addresses to DroneBL and EFBL checks. Set `false` to disable these checks and automatic DNSBL G-lines. |
| `glineDuration` | Sample `86400` | Positive duration in seconds for all G-lines. If missing or invalid, per-action defaults apply: 86400 seconds for DNSBL/words and 600 for repeated violations. |
| `violationUrl` | Empty (disabled) | Optional HTTP(S) link template for a recorded violation, with `{id}` as placeholder for its database ID. |

### Database

When `dbhost` and `db` are both present, startup connects through PostgreSQL JDBC and creates the `spamscan` schema and its `spamscan.channels` and `spamscan.id` tables if necessary. The schema initializer also adds a `lax` column if it is missing. The DB user needs permission to create or modify those objects, read `chanserv.users(username, flags)`, and read/write the scanner tables. `chanserv.users` belongs to an external service and is **not** created by this project.

Channels saved in `spamscan.channels` are joined after each completed burst. A violation reason is stored in `spamscan.id`, and its generated ID can appear in the disconnect message. With `dbhost` or `db` empty, persistence and ChanServ permission lookups are disabled; scanning still runs on observed channels. If a configured database cannot be reached or initialized, connection setup fails and retries after 10 seconds rather than silently switching to nonpersistent operation.

To link to a page for a particular recorded violation, configure a URL template such as `{"name":"violationUrl","value":"https://example.org/violations/{id}"}`. For violation ID `42`, the service then includes `ID: 42 (https://example.org/violations/42)` in the disconnect reason. When a voiced user is devoiced instead, the service sends that user a notice with the ID and link. Anti-knocker disconnects also include the link if they have a database ID. An empty, malformed, or non-HTTP(S) template falls back to showing the ID only. No link is emitted without a database-generated ID; configure the actual URL of your own violation viewer before enabling it.

### Rule Files

Both word-list files contain a JSON array. The scanner reads the `name` value of each entry; `value` may be empty:

```json
[
  {"name":"example phrase","value":""}
]
```

Missing word-list files mean empty lists. `BADWORD ADD` and `BADWORD DELETE` update the corresponding file using an atomic replacement; the directory must be writable and support atomic moves. Word matching uses a case-insensitive substring check after Unicode normalization. The `chars.txt` file supplies additional glyph mappings; if it is missing, Unicode NFKC-based detection still works.

## Detection And Actions

The service tracks P10 nick introductions/changes, account updates, channel bursts, joins, leaves, kicks, quits, disconnects, and mode changes. Messages are scanned only after `EB`, from known members of observed channels. Operator accounts identified by ChanServ flags `0x20`, `0x40`, or `0x200` are exempt. A user is considered registered when its tracked account is nonempty.

- Default score threshold: 15 for unregistered users, 25 for registered users. A lax channel adds 10 to the threshold, but only unregistered members within 300 seconds of joining are scanned there; other lax-channel messages are skipped.
- Homoglyphs within 300 seconds of a join: +10 points for a join under 60 seconds ago, otherwise +5. This check ends processing of that message.
- Repeating the previous line: +5 for a recent join or +2 otherwise. Messages that continue past this check add +3 or +1 for flooding, respectively.
- Ordinary badword: +15 for a recent join or +8 otherwise. Once the score reaches the threshold, the service records the reason (when DB-backed) and sanctions the user.
- G-line badword: immediate IP G-line if a usable IP is known, plus a channel sanction, independent of the score threshold. Ordinary badwords are checked first, so an overlapping ordinary match takes precedence.
- Scores decay by two points per ten seconds when next evaluated. Channel-burst members are not treated as newly joined merely because the service reconnected.

For a violation, a voiced member in a moderated channel is devoiced; otherwise the scanner sends a P10 disconnect (`D`). If an ID and `violationUrl` are available, disconnect reasons include the viewer link, while devoiced users receive it in a notice. Two violations for a user with a known IP also trigger an ident/IP G-line. At nick introduction, an anti-knocker nick/ident pattern can cause an immediate disconnect. For visible resolved IPv4 addresses, asynchronous DNSBL checks try DroneBL first, then EFBL; a hit generates an IP G-line. Hidden IPs and unresolved hosts are not checked. The sample `glineDuration` applies to all of these G-lines.

## Private Commands

Send a private message to the configured service nick. Commands are available only after the network burst. Replies use notices if the requester's ChanServ flags include `0x4`, otherwise private messages.

| Command | Access | Behavior |
| --- | --- | --- |
| `HELP`, `SHOWCOMMANDS`, `VERSION` | Tracked user | Show available commands or version. `HELP <command>` for administrator syntax requires privilege. |
| `AUTH <user> <password>` | Privileged account with configured admin credentials | Mark the requesting numeric as authorized for channel commands; authorization is not shared between users and is cleared on quit or reconnect. |
| `ADDCHAN <#channel>`, `DELCHAN <#channel>` | Privileged account or requester authorized with `AUTH`; DB required | Save and join an existing observed channel, or delete a saved channel and part it. |
| `BADWORD ADD <text>`, `BADWORD DELETE <text>`, `BADWORD LIST` | Privileged account | Edit or list ordinary badwords. Editing requires a writable rule-file directory. |
| `BADWORD GLINEADD <text>`, `BADWORD GLINEDELETE <text>`, `BADWORD GLINELIST` | Privileged account | Edit or list immediate-G-line badwords. |
| `SCORE <nick>` | Privileged account | Display the current, decayed spam score for a tracked nick. |

Privilege relies on the external `chanserv.users` table; without DB access only the public informational commands are available. Empty administrator credentials do not grant access to `AUTH`.

## Troubleshooting

- No connection: verify `host`, `port`, the server-link `password`, and P10 server registration. Check `error.log`; the relay retries after 10 seconds.
- No channel actions: ensure the burst has completed and the message sender and channel are tracked. Persistent joins and privilege checks need a configured, reachable PostgreSQL database.
- No badword matches: verify the JSON array shape and that the configured file path resolves from the working directory. Missing files start empty.
- No DNSBL actions: check `dnsbl`, host/IP visibility and IPv4 resolution. DNSBL access depends on external DNS responses.
- Daemon exits after printing a PID: inspect `daemon.log` and `error.log`. The parent only validates config readability; it does not wait for successful connection.

Run `mvn test` for local unit tests. `mvn clean package` runs those tests and builds the executable JAR. Live P10, PostgreSQL and DNSBL integration require the corresponding external services.

## License

This project is licensed under the **GNU General Public License version 2 only** (`GPL-2.0-only`). See the full text in [`LICENSE`](LICENSE).

Third-party notices are retained in [`NOTICE`](NOTICE). Dependencies retain their own licenses.
