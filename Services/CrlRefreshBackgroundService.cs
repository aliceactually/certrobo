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
                IReadOnlyList<CrlRefreshOutcome> outcomes = await caService.RefreshDueCrlsAsync(
                    TimeSpan.FromHours(24),
                    stoppingToken);
                foreach (CrlRefreshOutcome outcome in outcomes)
                {
                    if (outcome.Succeeded && outcome.PublishedCrl != null)
                    {
                        logger.LogInformation(
                            "Published refreshed CRL #{CrlNumber} for CA '{CaName}' (AuthorityId={AuthorityId}, NextUpdateUtc={NextUpdateUtc:O}).",
                            outcome.PublishedCrl.CrlNumber,
                            outcome.CaName,
                            outcome.CaAuthorityId,
                            outcome.PublishedCrl.NextUpdateUtc);
                    }
                    else
                    {
                        logger.LogWarning(
                            "CRL refresh failed for CA '{CaName}' (AuthorityId={AuthorityId}): {ErrorMessage}",
                            outcome.CaName,
                            outcome.CaAuthorityId,
                            outcome.ErrorMessage);
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
