# SANCTUM

[![Go version](https://img.shields.io/github/go-mod/go-version/deymosh/sanctum?logo=go)](./go.mod#L3)
[![GitHub Release](https://img.shields.io/github/v/release/deymosh/sanctum?link=https%3A%2F%2Fgithub.com%2Fdeymosh%2Fsanctum%2Freleases%2Flatest)](https://github.com/deymosh/sanctum/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![CI](https://github.com/deymosh/sanctum/actions/workflows/lint.yml/badge.svg)](https://github.com/deymosh/sanctum/actions/workflows/lint.yml)

SANCTUM is a sovereign, Tor-first personal relay for the Nostr protocol, for storing and backing up
sensitive notes like eCash, private chats, and drafts. It is a relay that is not so dumb, with
features like web of trust, whitelisting, blacklisting, JSONL backup / restore (including periodic
backups to the cloud), blastr note to other relays, and importing your old notes from other relays.
It even includes its own blossom media server!

> [!NOTE]
> SANCTUM is a hard fork of [HAVEN](https://github.com/barrydeen/haven) by [Barry Deen /
> Bitvora](https://bitvora.com), maintained independently once upstream declared itself feature
> complete. Differences from upstream: the relay stack is migrated to
> [fiatjaf.com/nostr](https://fiatjaf.com/nostr/) (LMDB is the only database engine), all outgoing
> connections can be routed through a SOCKS5 / Tor proxy via `PROXY_URL`, and the reference
> deployment is Docker Compose with a dedicated Tor sidecar.

## Four Relays in One + Blossom Media Server

**Private Relay**: This relay is only accessible by the owner of the relay and whitelisted npubs. It is used for
drafts, ecash, and other private notes that nobody else can read or write to. It is protected by Auth.

**Chat Relay**: This relay is used to contact the owner of the relay and whitelisted npubs by DM. Only people in the
web of trust can interact with this relay, protected by Auth. It only accepts encrypted DMs and group chat kinds.

**Inbox Relay**: This relay is where the owner of the relay and whitelisted npubs reads from. Send your zaps,
reactions, and replies to this relay when you're tagging the owner or one of the whitelisted npubs. You can also pull
notes from this relay if you want notes where the owner or whitelisted npub are tagged. This relay automatically pulls
notes from other relays. Only notes where the owner or whitelisted npubs are tagged will be accepted to this relay.

**Outbox Relay**: This relay is where the owner's and whitelisted npubs notes all live and are publicly accessible. You
can import all your old notes to this relay. All notes sent to this relay are blasted to other relays. Only the
owner and whitelisted npubs can send to this relay, but anyone can read.

**Blossom Media Server**: This relay also includes a media server for hosting images and videos. You can upload images
and videos to this relay and get a link to share them. Only the relay owner and whitelisted npubs can upload to this
relay, but anyone can view the images and videos.

## Not So Dumb Relay Features

**Web of Trust**: Protected from DM and Inbox spam by using a Web of Trust (WoT). See the [Web of Trust
Documentation](docs/wot.md) for more details.

**Access Control**: Whitelist and blacklist npubs, ban them from a nostr list you publish, and delete any event from
your relay. See the [Access Control Documentation](docs/access-control.md) for more details.

**Relay Management**: Run the relay from a web page signed in with a nostr browser extension, or over the
NIP-86 API: ban pubkeys, drop events, block addresses and rename each relay. The same page also **browses the notes
each relay is storing** — filter, search, inspect and delete them — and graphs the relay on a **dashboard**: traffic,
connections, accepted against rejected, the kind mix, top authors and storage, with 24-hour, 7-day and 30-day
history that survives a restart. See the [Relay Management Documentation](docs/relay-management.md) for more
details.

**Tor-first networking**: All outgoing relay traffic can be routed through a SOCKS5 proxy (a Tor daemon by default)
by setting `PROXY_URL`. `.onion` relay addresses are handled natively, and the bundled Docker Compose file runs a
dedicated Tor sidecar that both proxies outgoing connections and publishes the relay as a hidden service.

**Inbox Relay**: Notes are pulled from other relays and stored in the inbox relay.

**Blastr**: Notes sent to the outbox are also blasted to other relays.

**Import Old Notes**: Import your old notes and notes you're tagged in from other relays.

**Backup/Recover**: It is your data, manually export or import data JSONL at any time. Set periodic backups to the cloud
for easy recovery. See [Backup Documentation](docs/backup.md) for more details.

## Installation

### Option 1: Docker Compose with Tor (Recommended)

The reference deployment runs the relay and a Tor sidecar together, with everything the relay writes
kept under `./data`:

```bash
git clone https://github.com/deymosh/sanctum
cd sanctum
cp .env.example .env                    # then edit OWNER_NPUB, RELAY_URL and the relay names
cp relays_import.example.json relays_import.json
cp relays_blastr.example.json relays_blastr.json
docker compose up -d
```

The relay image is published to `ghcr.io/deymosh/sanctum`; the Tor sidecar uses
`ghcr.io/deymosh/tor`. Compose builds the relay image locally as a fallback when the published one
is not available.

Once Tor has bootstrapped, your relay's `.onion` address is in the hidden-service directory the
sidecar created:

```bash
cat ./tor/data/sanctum/hostname
```

To import your old notes in the Docker deployment, set `IMPORT_FLAG=true` in `.env` and restart the
relay container once; set it back to `false` afterwards.

### Option 2: Download Pre-built Binaries

Binaries for Linux, macOS and Windows are attached to each
[GitHub release](https://github.com/deymosh/sanctum/releases/):

```bash
mkdir sanctum
tar -xzf sanctum_[Platform]_[Architecture].tar.gz -C sanctum   # Windows: extract the .zip
```

### Option 3: Build from Source

See the [Build Documentation](docs/build.md).

## Setup Instructions

Follow these steps to get the Sanctum relay running on your local machine (after installing via Docker, binary
download or building from source):

### 1. Copy `.env.example` to `.env`

You'll need to create an `.env` file based on the example provided.

```bash
cp .env.example .env
```

### 2. Set your environment variables

Open the `.env` file and set the necessary environment variables. `LOG_LEVEL` sets logging (DEBUG,
INFO, WARNING or ERROR); `PROXY_URL` routes all outgoing connections through a SOCKS5 proxy — point
it at the Tor sidecar (`sanctum-tor:9050` under Compose) or your own daemon, and leave it empty to
connect directly.

### 3. Create the relays JSON files

Copy the example relays JSON files for your seed and blastr relays:

```bash
cp relays_import.example.json relays_import.json
```

```bash
cp relays_blastr.example.json relays_blastr.json
```

Customise the list of relays above as needed for your setup. The JSON should contain an array of relay URLs, which
default to wss:// if you don't explicitly specify the protocol.

> [!TIP]
> It is hard to keep an up-to-date list of working Nostr relays. Keep an eye on Sanctum's logs to see if any of the
> relays you're using are no longer working and replace them accordingly. There is no guarantee that the example relays
> will be up and running at all times (or at all), and it is up to the user to keep their relay list up to date.


### 4. Configure Access Control (optional)

Sanctum allows you to whitelist specific npubs to grant them full relay access or blacklist them to prevent any
interaction with your relay.

See the [Access Control Documentation](docs/access-control.md) for more details on how to set up whitelists and blacklists.

### 5. Run on System Startup

#### Linux – Create a Systemd Service

<details><summary>Click here to view the installation routine for Systemd</summary>
<p>

To have the relay run as a service, create a systemd unit file. Make sure to limit the memory usage to less than your
system's total memory to prevent the relay from crashing the system. Replace the values for `ExecStart` and
`WorkingDirectory` with the actual paths where you installed Sanctum and stored the `.env` file.

1. Create the file:

   ```bash
   sudo nano /etc/systemd/system/sanctum.service
   ```

2. Add the following contents:

   ```ini
   [Unit]
   Description=Sanctum Relay
   After=network.target

   [Service]
   ExecStart=/home/ubuntu/sanctum/sanctum #Edit path to point to where you installed Sanctum
   WorkingDirectory=/home/ubuntu/sanctum #Edit path to point to where you installed Sanctum
   MemoryMax=1000M  # Example, Limit memory usage to 1000 MB | Edit this to fit your machine
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

3. Reload systemd to recognize the new service:

   ```bash
   sudo systemctl daemon-reload
   ```

4. Start the service:

   ```bash
   sudo systemctl start sanctum
   ```

5. (Optional) Enable the service to start on boot:

   ```bash
   sudo systemctl enable sanctum
   ```

</p>
</details>

#### macOS - Create a login item App

<details><summary>Click here to view the installation routine for macOS</summary>
<p>

To have the relay run on boot, create a script that will open the terminal and run the sanctum binary, the terminal will
remain open and the relay running with it. Be sure the download `/sanctum` directory is located in the macOS home
folder `~/`

1. Create the App: Open Script Editor

2. Add the following contents:

   ```ini
   tell application "Terminal"
     activate
     do script "cd \"$HOME/sanctum\"; ./sanctum; exec $SHELL"
   end tell
   ```
3. Save in the Applications folder

4. Open System - Settings - General - Login Items
   Hit the plus, add run_sanctum from the Applications folder

5. Reboot – On initial restart and terminal auto-open, choose “allow”

6. Reboot again to test the login item

</p>
</details>

### 6. Set up a Reverse Proxy (optional)

To have a domain name (example: relay.domain.com) point to your machine, you will need to set up a reverse proxy.

#### Nginx

<details><summary>Click here to view the installation routine for Nginx</summary>
<p>

1. Install nginx on your relay:

   ```bash
   sudo apt-get update
   sudo apt-get install nginx
   ```

2. Remove default config: `sudo rm -rf /etc/nginx/sites-available/default`

3. Create new default config: `sudo nano /etc/nginx/sites-available/default`

4. Add a new reverse proxy config by adding the following configuration to your nginx configuration file:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    client_max_body_size 100m;

    location / {
        proxy_pass http://localhost:3355;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Replace `yourdomain.com` with your actual domain name.

> [!IMPORTANT]
> `X-Forwarded-For` is set to `$remote_addr`, not the more common `$proxy_add_x_forwarded_for`. The latter *appends*
> the real client address to whatever the client sent, which lets a client prepend a forged one — Sanctum reads the
> leftmost entry, so the forgery would win. This matters for the rate limiters and for
> [IP blocking](docs/relay-management.md#blocking-addresses).

After adding the configuration, restart nginx:

```bash
sudo systemctl restart nginx
```

</p>
</details>

#### Apache

<details><summary>Click here to view the installation routine for Apache</summary>
<p>

1. Install Apache on your server
2. Set up a virtual host:
   ```apache
   <VirtualHost *:80>
           ServerName yourdomain.com

           RewriteEngine On
           RewriteCond %{HTTP:Upgrade} websocket [NC]
           RewriteCond %{HTTP:Connection} upgrade [NC]
           RewriteRule ^/?(.*) "ws://localhost:3355/$1" [P,L]

           # Proxy for HTTP traffic (NIP-11 relay info page)
           ProxyPass / http://localhost:3355/
           ProxyPassReverse / http://localhost:3355/

           # Overwrite whatever the client sent, so a forged X-Forwarded-For
           # cannot win: mod_proxy appends to the header rather than replacing it
           RequestHeader set X-Forwarded-For "expr=%{REMOTE_ADDR}"

           # Optional: Add HSTS header for enhanced security
           Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

           # Optional: Set appropriate WebSocket headers
           RequestHeader set Upgrade "websocket"
           RequestHeader set Connection "Upgrade"
   </VirtualHost>
   ```

Replace `yourdomain.com` with your actual domain name.

```bash
sudo systemctl restart httpd
```

</p>
</details>

#### Caddy
<details><summary>Click here to view the installation routine for Caddy</summary>
<p>

Preparation: Set the A record (for your domain) to point to the server's IP address.

1. Install caddy:

   ```bash
   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt update
   sudo apt install caddy
   ```

2. Open Caddyfile:

   ```bash
   sudo nano /etc/caddy/Caddyfile
   ```

3. Add configuration:

   ```bash
   # Configuration for SANCTUM Relay
   yourdomain.com {
       reverse_proxy localhost:3355 {
           header_up Host {host}
           header_up X-Real-IP {remote_host}
           header_up X-Forwarded-For {remote_host}
           header_up X-Forwarded-Proto {scheme}
           transport http {
               versions 1.1
           }
       }
       request_body {
           max_size 100MB
       }
   }
   ```

4. Reload Caddy:

   ```bash
   sudo systemctl reload caddy
   ```

5. Check status logs:

```bash
sudo systemctl status caddy
sudo journalctl -u caddy -f --since "2 hour ago"
```

**Note:** Caddy automatically manages certificates and WebSocket connections. Certbot is not required.

</p>
</details>

### 7. Install Certbot (optional)

If you want to serve the relay over HTTPS, you can use Certbot to generate an SSL certificate.

```bash
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx
```

After installing Certbot, run the following command to generate an SSL certificate:

```bash
sudo certbot --nginx
```

Apache:

```bash
sudo certbot --apache
```

Follow the instructions to generate the certificate.

> [!NOTE]
> The `cerbot` command will fail if the Domain you added to nginx is not yet pointing at your machine's IP address.
> This is done by adding an A record subdomain pointing to your IP address through your DNS recrods Manager.

### 8. Import your old notes (optional)

If you want to import your old notes and notes you're tagged in from other relays, run the following command:

```bash
sudo systemctl stop sanctum
./sanctum import
sudo systemctl start sanctum
```

### 9. Access the relay

Once everything is set up, the relay will be running on `localhost:3355` with the following endpoints:

- `localhost:3355` (outbox and Blossom server)
- `localhost:3355/private`
- `localhost:3355/chat`
- `localhost:3355/inbox`
- `localhost:3355/admin` (relay management, notes browser and dashboard, signed in with a nostr browser extension)

See [Relay Management](docs/relay-management.md) for the admin page and the NIP-86 API behind it.

## Database

Sanctum stores notes in [LMDB](https://www.symas.com/mdb), an embedded database, meaning no external database is
required. BadgerDB is no longer supported; to move an existing BadgerDB relay over, [back it up](docs/backup.md) with a
HAVEN version that still reads it and restore the backup into the new one.

LMDB performs best with NVMe drives and may require fine-tuning based on factors such as database size, operating
system, file system, and hardware.

### LMDB Map Size

There is no one-size-fits-all value for LMDB’s map size. Windows and macOS users, in particular, may need
to adjust the `LMDB_MAPSIZE` environment variable to a value lower than the available free disk space if the default
value of 273 GB is too high. Otherwise, Sanctum will fail to bootstrap. Users with large databases may also need to
increase the `LMDB_MAPSIZE` value above the default. On most systems, the default value should work fine.

Despite the large default value, on most modern systems LMDB will only use the disk space it needs. The map size simply
defines an upper limit for the database size. For more information about LMDB’s map size, refer to the
[LMDB documentation](http://www.lmdb.tech/doc/group__mdb.html#gaa2506ec8dab3d969b0e609cd82e619e5).

### Migrating from databases created in older versions

Sanctum uses the [fiatjaf.com/nostr event store](https://pkg.go.dev/fiatjaf.com/nostr/eventstore) to store notes. The
way events are stored evolves over time, and occasionally this introduces breaking changes.

As a precaution, before upgrading to a newer version of Sanctum, you should back up the `db` folder.

HAVEN versions 1.0.3 and earlier did not replace outdated notes. While this does not affect the relay's core
functionality, it can result in a bloated database, reduced performance, and bugs in some clients. For this reason, it
is recommended to delete old databases and start fresh, optionally [re-importing](#8-import-your-old-notes-optional)
your previous notes.

## Blossom Media Server

The outbox relay also functions as a media server for hosting images and videos. You can upload media files to the relay
and get a shareable link. Only the relay owner and whitelisted npubs have upload permissions to the media server,
but anyone can view the hosted images and videos.

Media files are stored in the file system based on the `BLOSSOM_PATH` environment variable set in the `.env` file.
The default path is `./blossom`.

> [!IMPORTANT]
> Give `BLOSSOM_PATH` a trailing slash, as `.env.example` does. The path is joined to the file name by
> concatenation, so `BLOSSOM_PATH="blossom"` writes media *beside* the `blossom` directory rather than inside it,
> as `./blossom<hash>`. Sanctum warns at startup when it sees this. It is not corrected automatically, because doing
> so would hide every file already written that way.

Browse and manage what has been uploaded from the **Media** view of the [admin page](docs/relay-management.md#media):
filter, search and sort the whole library, delete media, block a hash so the same bytes cannot be uploaded again,
and reconcile the index against what is actually on disk.

> [!WARNING]
> Cloud backups cover the media **index**, not the media **files**. Back up your `BLOSSOM_PATH` directory
> separately. Restoring a backup without it leaves every entry pointing at a file that is no longer there.

## Cloud Backups

Sanctum can back up and restore your notes using a portable JSONL format. This can be done either with the built-in
`./sanctum backup` and `./sanctum restore` commands, or with a scheduled backup periodically uploaded to your cloud
storage.

See [Backup Documentation](docs/backup.md#periodic-cloud-backups) and
[Cloud Storage Provider Specific Instructions](docs/cloud-storage.md) for further details.

## License

This project is licensed under the [MIT](./LICENSE) License.
