using CertRobo.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CertRobo.Services;

public sealed class CrlRefreshBackgroundService(
    CertificateAuthorityService caService,
    ILogger<CrlRefreshBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var latest = await caService.GetLatestCrlAsync(stoppingToken);
                var activeCa = await caService.GetActiveAuthorityAsync(stoppingToken);
                if (activeCa != null)
                {
                    DateTimeOffset now = DateTimeOffset.UtcNow;
                    bool shouldRefresh = latest == null
                        || latest.NextUpdateUtc <= now.AddHours(24);

                    if (shouldRefresh && !string.IsNullOrEmpty(caService.ResolveEffectivePassphrase()))
                    {
                        var refreshed = await caService.RefreshActiveCrlAsync(stoppingToken);
                        if (refreshed != null)
                        {
                            logger.LogInformation(
                                "Published refreshed CRL #{CrlNumber} for CA '{CaName}' (NextUpdateUtc={NextUpdateUtc:O}).",
                                refreshed.CrlNumber,
                                activeCa.Name,
                                refreshed.NextUpdateUtc);
                        }
                    }
                    else if (shouldRefresh)
                    {
                        logger.LogWarning(
                            "CRL for CA '{CaName}' is due for refresh (NextUpdateUtc={NextUpdateUtc:O}), but the CA signing key is locked.",
                            activeCa.Name,
                            latest?.NextUpdateUtc);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduled CRL refresh encountered an error.");
            }

            try
            {
                await Task.Delay(CheckInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
