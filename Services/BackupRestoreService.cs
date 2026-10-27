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
            if (File.Exists(tempSnapshotDb))
            {
                File.Delete(tempSnapshotDb);
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
