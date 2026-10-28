using CertRobo.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.IO.Compression;

namespace CertRobo.Services;

/// <summary>
/// Provides consistent online backup and restore of the SQLite database, encrypted CA signing key(s),
/// and ASP.NET Core DataProtection key ring.
/// </summary>
public sealed class BackupRestoreService(
    IDbContextFactory<CertRoboDbContext> dbFactory,
    CaKeyCustodyOptions caOptions)
{
    public async Task<byte[]> CreateConsistentBackupArchiveAsync(
        string sqliteFilePath,
        string dataProtectionKeysDir,
        CancellationToken cancellationToken = default)
    {
        string tempSnapshotDb = Path.Combine(Path.GetTempPath(), $"certrobo-backup-{Guid.NewGuid():N}.db");
        await CertificateAuthorityService.AcquireLifecycleLockAsync(cancellationToken);
        try
        {
            await using (CertRoboDbContext db = await dbFactory.CreateDbContextAsync(cancellationToken))
            {
                string vacuumSql = "VACUUM INTO '" + tempSnapshotDb.Replace("'", "''") + "';";
#pragma warning disable EF1002
                await db.Database.ExecuteSqlRawAsync(vacuumSql, cancellationToken);
#pragma warning restore EF1002
            }

            using MemoryStream ms = new();
            using (ZipArchive zip = new(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                if (File.Exists(tempSnapshotDb))
                {
                    zip.CreateEntryFromFile(tempSnapshotDb, "database/certrobo.db");
                }
                else if (File.Exists(sqliteFilePath))
                {
                    zip.CreateEntryFromFile(sqliteFilePath, "database/certrobo.db");
                }

                if (Directory.Exists(caOptions.StorageDirectory))
                {
                    foreach (string keyFile in Directory.GetFiles(caOptions.StorageDirectory, "*.p8.enc"))
                    {
                        zip.CreateEntryFromFile(keyFile, $"ca/{Path.GetFileName(keyFile)}");
                    }
                }

                if (Directory.Exists(dataProtectionKeysDir))
                {
                    foreach (string dpFile in Directory.GetFiles(dataProtectionKeysDir, "*.xml"))
                    {
                        zip.CreateEntryFromFile(dpFile, $"dataprotection/{Path.GetFileName(dpFile)}");
                    }
                }
            }

            return ms.ToArray();
        }
        finally
        {
            try
            {
                if (File.Exists(tempSnapshotDb))
                {
                    File.Delete(tempSnapshotDb);
                }
            }
            finally
            {
                CertificateAuthorityService.ReleaseLifecycleLock();
            }
        }
    }

    public static void RestoreBackupArchive(
        byte[] archiveBytes,
        string targetSqliteFilePath,
        string targetCaStorageDir,
        string targetDataProtectionKeysDir)
    {
        SqliteConnection.ClearAllPools();

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(targetSqliteFilePath))!);
        Directory.CreateDirectory(targetCaStorageDir);
        Directory.CreateDirectory(targetDataProtectionKeysDir);

        using MemoryStream ms = new(archiveBytes);
        using ZipArchive zip = new(ms, ZipArchiveMode.Read);

        foreach (ZipArchiveEntry entry in zip.Entries)
        {
            if (entry.FullName == "database/certrobo.db")
            {
                entry.ExtractToFile(targetSqliteFilePath, overwrite: true);
                RestrictFilePermissionsIfUnix(targetSqliteFilePath);
            }
            else if (entry.FullName.StartsWith("ca/", StringComparison.Ordinal) && entry.FullName.EndsWith(".p8.enc", StringComparison.Ordinal))
            {
                string fileName = Path.GetFileName(entry.FullName);
                string destPath = Path.Combine(targetCaStorageDir, fileName);
                entry.ExtractToFile(destPath, overwrite: true);
                RestrictFilePermissionsIfUnix(destPath);
            }
            else if (entry.FullName.StartsWith("dataprotection/", StringComparison.Ordinal) && entry.FullName.EndsWith(".xml", StringComparison.Ordinal))
            {
                string fileName = Path.GetFileName(entry.FullName);
                string destPath = Path.Combine(targetDataProtectionKeysDir, fileName);
                entry.ExtractToFile(destPath, overwrite: true);
                RestrictFilePermissionsIfUnix(destPath);
            }
        }

        RewriteRestoredKeyPaths(targetSqliteFilePath, targetCaStorageDir);
    }

    private static void RewriteRestoredKeyPaths(string sqliteFilePath, string caStorageDir)
    {
        if (!File.Exists(sqliteFilePath))
        {
            return;
        }

        using SqliteConnection connection = new($"Data Source={sqliteFilePath}");
        connection.Open();

        RewriteTableKeyPaths(connection, "CaAuthorities");
        RewriteTableKeyPaths(connection, "PendingCaEnrollments");

        void RewriteTableKeyPaths(SqliteConnection db, string tableName)
        {
            using SqliteCommand exists = db.CreateCommand();
            exists.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$tableName";
            exists.Parameters.AddWithValue("$tableName", tableName);
            if (Convert.ToInt64(exists.ExecuteScalar()) == 0)
            {
                return;
            }

            List<(long Id, string ExistingPath)> records = [];
            using (SqliteCommand select = db.CreateCommand())
            {
                select.CommandText = $"SELECT Id, EncryptedPrivateKeyPath FROM \"{tableName}\"";
                using SqliteDataReader reader = select.ExecuteReader();
                while (reader.Read())
                {
                    records.Add((reader.GetInt64(0), reader.GetString(1)));
                }
            }

            foreach ((long id, string existingPath) in records)
            {
                string restoredPath = Path.Combine(caStorageDir, Path.GetFileName(existingPath));
                using SqliteCommand update = db.CreateCommand();
                update.CommandText = $"UPDATE \"{tableName}\" SET EncryptedPrivateKeyPath=$path WHERE Id=$id";
                update.Parameters.AddWithValue("$path", restoredPath);
                update.Parameters.AddWithValue("$id", id);
                update.ExecuteNonQuery();
            }
        }
    }

    private static void RestrictFilePermissionsIfUnix(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // Ignore if filesystem does not support UnixFileMode
            }
        }
    }
}
