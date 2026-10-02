# Backup and Restore

### Corrected version

Sanctum provides tools for backing up and restoring your relay data. This is essential for several use cases:

* **Disaster Recovery**: Protect your data against hardware failure or accidental deletion.
* **Switching Databases**: Move your data when migrating to a new server or database provider, or out of a BadgerDB
  database written by an older version of Sanctum.
* **Importing/Exporting Data**: Move data between Sanctum and other Nostr relays.

> [!IMPORTANT]
> When importing data from external JSONL files, Sanctum will trust all events contained within the file and will not try
> to validate or split the data. For example, it will allow notes from other people to be imported into your Outbox 
> relay, bypassing [WoT](wot.md) checks and other safeguards. This is intentional to allow for maximum flexibility when 
> importing data, but it also means that you should be careful when importing data from untrusted sources.

> [!TIP]
> For simple imports from external relays, you may prefer to use the
> [`./sanctum import`](../README.md#8-import-your-old-notes-optional) command instead.

---

## Manual Backup

If you want to back up all relay data to a JSONL zip file, run the following command:

```bash
./sanctum backup
```

This will create a `sanctum_backup.zip` file in your current directory. You can specify a different filename:

```bash
./sanctum backup mybackup.zip
```

If you want to upload the backup to your cloud provider after creation, use the `--to-cloud` flag:

```bash
./sanctum backup --to-cloud
```

You can also specify a filename with `--to-cloud`:

```bash
./sanctum backup --to-cloud mybackup.zip
```

To back up a specific relay to a JSONL file:

```bash
./sanctum backup --relay outbox outbox.jsonl
```

And you can also upload a specific relay backup to the cloud:

```bash
./sanctum backup --relay outbox --to-cloud outbox.jsonl
```

## Manual Restore

To restore data from a `sanctum_backup.zip` file, run:

```bash
./sanctum restore
```

This will look for a `sanctum_backup.zip` file in your current directory. You can specify a different filename:

```bash
./sanctum restore mybackup.zip
```

To restore from the cloud using the default name:

```bash
./sanctum restore --from-cloud
```

You can also specify a filename to restore from the cloud:

```bash
./sanctum restore --from-cloud mybackup.zip
```

To restore a specific relay from a JSONL file:

```bash
./sanctum restore --relay outbox outbox.jsonl
```

And to restore a specific relay from a JSONL file in the cloud:

```bash
./sanctum restore --relay outbox --from-cloud outbox.jsonl
```

## Periodic Cloud Backups

Sanctum can periodically back up your data to a cloud provider of your choice.

To back up your database to S3 compatible storage such as [AWS S3](https://aws.amazon.com/s3/), 
[GCP Cloud Storage](https://cloud.google.com/storage), 
[DigitalOcean Spaces](https://www.digitalocean.com/products/spaces) or
[Cloudflare R2](https://www.cloudflare.com/developer-platform/r2/).

First, you need to create the bucket on your provider. After creating the Bucket, you will be provided with:

- Access Key ID
- Secret Key
- URL Endpoint
- Region
- Bucket Name

Once you have this data, update your `.env` file with the appropriate information:

```Dotenv
S3_ACCESS_KEY_ID="your_access_key_id"
S3_SECRET_KEY="your_secret_key"
S3_ENDPOINT="your_endpoint"
S3_REGION="your_region"
S3_BUCKET_NAME="your_bucket"
```

Replace `your_access_key_id`, `your_secret_access_key`, `your_region`, and `your_bucket` with your actual credentials.

You may also want to set the `BACKUP_INTERVAL_HOURS` environment variable to specify how often the relay should back up 
the database.

```Dotenv
BACKUP_INTERVAL_HOURS=24
```

Finally, you need to specifiy `s3` as the backup provider:

```Dotenv
BACKUP_PROVIDER="s3" # s3, none (or leave blank to disable)
```

See [Cloud Storage Provider Specific Instructions](cloud-storage.md) for more details.

---

[README](../README.md) | [Cloud Storage](cloud-storage.md) 