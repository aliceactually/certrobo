using CertRobo.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CertRobo.Services;

public sealed class CrlRefreshBackgroundService(
    CertificateAuthorityService caService,
    ILogger<CrlRefreshBackgroundService> logger,
    TimeSpan? checkIntervalOverride = null,
    TimeSpan? pendingRetryIntervalOverride = null) : BackgroundService
{
    public static readonly TimeSpan DefaultCheckInterval = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan DefaultPendingRetryInterval = TimeSpan.FromSeconds(15);

    private readonly TimeSpan _checkInterval = checkIntervalOverride ?? DefaultCheckInterval;
    private readonly TimeSpan _pendingRetryInterval = pendingRetryIntervalOverride ?? DefaultPendingRetryInterval;
    private long _completedScanCount;
    private TaskCompletionSource<long> _scanCompletedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object _scanSync = new();

    public long CompletedScanCount => Interlocked.Read(ref _completedScanCount);

    public async Task<long> WaitForCompletedScanCountAsync(
        long minimumScanCount,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        while (true)
        {
            long current = Interlocked.Read(ref _completedScanCount);
            if (current >= minimumScanCount)
            {
                return current;
            }

            Task<long> waitTask;
            lock (_scanSync)
            {
                current = Interlocked.Read(ref _completedScanCount);
                if (current >= minimumScanCount)
                {
                    return current;
                }
                waitTask = _scanCompletedTcs.Task;
            }

            await waitTask.WaitAsync(cts.Token);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            bool anyPendingOrFailed = false;
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
                        anyPendingOrFailed = true;
                        logger.LogWarning(
                            "CRL refresh failed for CA '{CaName}' (AuthorityId={AuthorityId}): {ErrorMessage}",
                            outcome.CaName,
                            outcome.CaAuthorityId,
                            outcome.ErrorMessage);
                    }
                }

                if (!anyPendingOrFailed)
                {
                    IReadOnlySet<int> remainingUnpublished =
                        await caService.GetCertificateIdsWithUnpublishedRevocationsAsync(stoppingToken);
                    if (remainingUnpublished.Count > 0)
                    {
                        anyPendingOrFailed = true;
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                anyPendingOrFailed = true;
                logger.LogError(ex, "Scheduled CRL refresh encountered an error.");
            }
            finally
            {
                lock (_scanSync)
                {
                    long nextCount = Interlocked.Increment(ref _completedScanCount);
                    TaskCompletionSource<long> completed = _scanCompletedTcs;
                    _scanCompletedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    completed.TrySetResult(nextCount);
                }
            }

            try
            {
                TimeSpan waitDuration = anyPendingOrFailed ? _pendingRetryInterval : _checkInterval;
                await caService.WaitForCrlRefreshSignalAsync(waitDuration, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
