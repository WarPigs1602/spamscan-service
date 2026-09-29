# spamscan-service

Standalone P10 relay for newserv spam scanning. The relay connects directly to the IRC server and forwards traffic for spam analysis without performing SASL authentication or credential verification.

## Overview

This project connects as a P10 server to an IRC network and monitors traffic for spam scanning purposes. It is intentionally kept minimal and does not handle SASL, authentication, or remoteauth.

## Build

### Windows

```powershell
./mvnw.cmd package
```

### Linux

```bash
./mvnw package
```

The generated runnable artifact is:

```text
target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Run

### Windows

```powershell
java -jar target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar config.json
```

### Linux

```bash
java -jar target/spamscan-service-1.0-SNAPSHOT-jar-with-dependencies.jar config.json
```

## Configuration

The configuration is loaded from `config.json` and contains the server connection details.

## Notes

- This project is intentionally kept as a standalone relay implementation.
- SASL, authentication, and credential verification are not included.
- The build is managed with Maven and the packaged jar is produced by the assembly plugin.

## License

This project is licensed under the GNU General Public License v2.0.

See the full text in the `LICENSE` file in this repository.
