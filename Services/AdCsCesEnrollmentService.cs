using CertRobo.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Security;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace CertRobo.Services;

public enum AdCsCesOutcomeKind
{
    IssuedReadyForActivation,
    IssuedAwaitingChainAnchor,
    PendingApproval,
    Denied,
    AuthenticationFailure,
    TlsOrTrustFailure,
    TransportFailure,
    SubmissionUncertain,
    ValidationFailure
}

public sealed record AdCsCesOperationResult(
    bool Succeeded,
    AdCsCesOutcomeKind OutcomeKind,
    string SummaryMessage,
    string? UpstreamRequestId = null,
    string? UpstreamErrorCode = null,
    string? DispositionMessage = null,
    PendingCaEnrollmentRecord? UpdatedRecord = null);

public sealed record AdCsCesTransportOptions(
    Uri EndpointUri,
    string AuthenticationMode,
    string? CustomServerTlsTrustPem,
    string? ClientCertificatePem,
    string? ClientPrivateKeyPem,
    TimeSpan Timeout);

/// <summary>
/// Optional Microsoft AD CS Certificate Enrollment Web Service (CES) connector implementing [MS-WSTEP]
/// over HTTPS/SOAP 1.2 without requiring Active Directory domain membership or Windows-only APIs.
/// </summary>
public sealed class AdCsCesEnrollmentService
{
    private static readonly SemaphoreSlim CesSubmissionLock = new(1, 1);

    public const string WstepActionUri = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep";
    public const string WsTrustIssueUri = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
    public const string WstepQueryTokenStatusUri = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus";
    public const string X509v3TokenTypeUri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public const string Pkcs10ValueTypeUri = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10";
    public const string Base64EncodingTypeUri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";
    public const string UsernameTokenPasswordTextUri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
    public const int MaxCesResponseBytes = 2 * 1024 * 1024;
    public const int MaxBinarySecurityTokensPerResponse = 16;

    private static readonly XNamespace Soap12Ns = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace WsaNs = "http://www.w3.org/2005/08/addressing";
    private static readonly XNamespace WsuNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static readonly XNamespace WsseNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace WstNs = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace WstepNs = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
    private static readonly XNamespace AcNs = "http://schemas.xmlsoap.org/ws/2006/12/authorization";

    private readonly IDbContextFactory<CertRoboDbContext> _dbFactory;
    private readonly CertificateAuthorityService _caService;
    private readonly IDataProtector _credentialProtector;
    private readonly Func<AdCsCesTransportOptions, HttpMessageHandler> _handlerFactory;

    public AdCsCesEnrollmentService(
        IDbContextFactory<CertRoboDbContext> dbFactory,
        CertificateAuthorityService caService,
        IDataProtectionProvider dataProtectionProvider,
        Func<AdCsCesTransportOptions, HttpMessageHandler>? customHandlerFactory = null)
    {
        _dbFactory = dbFactory;
        _caService = caService;
        _credentialProtector = dataProtectionProvider.CreateProtector("CertRobo.AdCsCesConnector.Credentials.v1");
        _handlerFactory = customHandlerFactory ?? CreateDefaultSocketsHttpHandler;
    }

    public async Task<AdCsCesConnectorConfig> GetConfigAsync(CancellationToken cancellationToken = default)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);

        AdCsCesConnectorConfig? config = await db.AdCsCesConfigs
            .OrderBy(c => c.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (config == null)
        {
            config = new AdCsCesConnectorConfig
            {
                Id = 1,
                IsEnabled = false,
                AuthenticationMode = "UsernamePassword",
                RequestTimeoutSeconds = 30
            };
            db.AdCsCesConfigs.Add(config);
            await db.SaveChangesAsync(cancellationToken);
        }

        return config;
    }

    public async Task<(bool Succeeded, string? ErrorMessage, AdCsCesConnectorConfig? Config)> SaveConfigAsync(
        bool isEnabled,
        string endpointUrl,
        string certificateTemplate,
        string authenticationMode,
        string username,
        string? newPassword,
        bool clearSavedPassword,
        string clientCertificatePem,
        string? newClientPrivateKeyPem,
        bool clearSavedClientKey,
        string customServerTlsTrustPem,
        string defaultParentChainTrustPem,
        int requestTimeoutSeconds,
        CancellationToken cancellationToken = default)
    {
        string trimmedEndpoint = (endpointUrl ?? string.Empty).Trim();
        string trimmedTemplate = (certificateTemplate ?? string.Empty).Trim();
        string normalizedAuthMode = string.Equals(authenticationMode, "ClientCertificate", StringComparison.OrdinalIgnoreCase)
            ? "ClientCertificate"
            : "UsernamePassword";

        if (isEnabled || !string.IsNullOrEmpty(trimmedEndpoint))
        {
            if (!Uri.TryCreate(trimmedEndpoint, UriKind.Absolute, out Uri? parsedUri)
                || !string.Equals(parsedUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return (false, "AD CS CES Endpoint URL must be a valid HTTPS URL (https://...). Plain HTTP is not permitted.", null);
            }
        }

        if (isEnabled && string.IsNullOrWhiteSpace(trimmedTemplate))
        {
            return (false, "Certificate Template name (e.g. SubCA) is required when the AD CS CES connector is enabled.", null);
        }

        if (!string.IsNullOrWhiteSpace(customServerTlsTrustPem))
        {
            try
            {
                List<X509Certificate2> tlsCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                    null, customServerTlsTrustPem, "CES TLS Trust CA bundle");
                if (tlsCerts.Count == 0)
                {
                    return (false, "No valid X.509 certificates were found in the CES TLS Trust CA bundle.", null);
                }
                bool hasSelfSignedRoot = tlsCerts.Any(CaChainAndConstraintValidator.IsSelfSignedCryptographically);
                foreach (X509Certificate2 c in tlsCerts) c.Dispose();
                if (!hasSelfSignedRoot)
                {
                    return (
                        false,
                        "CES TLS Trust CA bundle must include an explicitly trusted self-signed root CA (intermediate certificates may be included alongside it).",
                        null);
                }
            }
            catch (Exception ex)
            {
                return (false, ex.Message, null);
            }
        }

        if (!string.IsNullOrWhiteSpace(defaultParentChainTrustPem))
        {
            try
            {
                List<X509Certificate2> chainCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                    null, defaultParentChainTrustPem, "Parent/Root CA Chain bundle");
                foreach (X509Certificate2 c in chainCerts) c.Dispose();
                if (chainCerts.Count == 0)
                {
                    return (false, "No valid X.509 certificates were found in the Parent/Root CA Chain bundle.", null);
                }
            }
            catch (Exception ex)
            {
                return (false, ex.Message, null);
            }
        }

        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await db.EnsureSchemaUpgradedAsync(cancellationToken);

        AdCsCesConnectorConfig? existing = await db.AdCsCesConfigs
            .OrderBy(c => c.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (existing == null)
        {
            existing = new AdCsCesConnectorConfig { Id = 1 };
            db.AdCsCesConfigs.Add(existing);
        }

        existing.IsEnabled = isEnabled;
        existing.EndpointUrl = trimmedEndpoint;
        existing.CertificateTemplate = trimmedTemplate;
        existing.AuthenticationMode = normalizedAuthMode;
        existing.Username = (username ?? string.Empty).Trim();
        existing.ClientCertificatePem = (clientCertificatePem ?? string.Empty).Trim();
        existing.CustomServerTlsTrustPem = (customServerTlsTrustPem ?? string.Empty).Trim();
        existing.DefaultParentChainTrustPem = (defaultParentChainTrustPem ?? string.Empty).Trim();
        existing.RequestTimeoutSeconds = Math.Clamp(requestTimeoutSeconds, 5, 120);
        existing.UpdatedAtUtc = DateTimeOffset.UtcNow;

        if (clearSavedPassword)
        {
            existing.ProtectedPassword = string.Empty;
        }
        else if (!string.IsNullOrEmpty(newPassword))
        {
            existing.ProtectedPassword = _credentialProtector.Protect(newPassword);
        }

        if (clearSavedClientKey)
        {
            existing.ProtectedClientPrivateKeyPem = string.Empty;
        }
        else if (!string.IsNullOrWhiteSpace(newClientPrivateKeyPem))
        {
            existing.ProtectedClientPrivateKeyPem = _credentialProtector.Protect(newClientPrivateKeyPem.Trim());
        }

        if (normalizedAuthMode == "ClientCertificate" && isEnabled)
        {
            if (string.IsNullOrWhiteSpace(existing.ClientCertificatePem) || string.IsNullOrWhiteSpace(existing.ProtectedClientPrivateKeyPem))
            {
                return (false, "Client Certificate Authentication requires both a client certificate PEM and a client private key PEM.", null);
            }

            string decryptedKey = _credentialProtector.Unprotect(existing.ProtectedClientPrivateKeyPem);
            if (!PkcsBuilder.CertKeyCheck(existing.ClientCertificatePem, decryptedKey))
            {
                return (false, "The configured client certificate and client private key do not match.", null);
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        return (true, null, existing);
    }

    /// <summary>
    /// Submits a pending CA enrollment CSR to Microsoft AD CS CES via [MS-WSTEP] RequestSecurityToken (Issue).
    /// Prevents blind resubmission when a prior attempt resulted in SubmissionUncertain or AwaitingApproval
    /// unless forceResubmit is explicitly true.
    /// </summary>
    public async Task<AdCsCesOperationResult> SubmitPendingEnrollmentAsync(
        int pendingEnrollmentId,
        string? oneTimePasswordOverride = null,
        string? templateOverride = null,
        bool forceResubmit = false,
        CancellationToken cancellationToken = default)
    {
        await CesSubmissionLock.WaitAsync(cancellationToken);
        try
        {
            return await SubmitPendingEnrollmentCoreAsync(
                pendingEnrollmentId,
                oneTimePasswordOverride,
                templateOverride,
                forceResubmit,
                cancellationToken);
        }
        finally
        {
            CesSubmissionLock.Release();
        }
    }

    private async Task<AdCsCesOperationResult> SubmitPendingEnrollmentCoreAsync(
        int pendingEnrollmentId,
        string? oneTimePasswordOverride = null,
        string? templateOverride = null,
        bool forceResubmit = false,
        CancellationToken cancellationToken = default)
    {
        AdCsCesConnectorConfig config = await GetConfigAsync(cancellationToken);
        if (!config.IsEnabled)
        {
            return new(
                false,
                AdCsCesOutcomeKind.ValidationFailure,
                "The Microsoft AD CS CES connector is disabled. Enable and configure it first, or complete enrolment manually.");
        }

        if (!Uri.TryCreate(config.EndpointUrl, UriKind.Absolute, out Uri? endpointUri)
            || !string.Equals(endpointUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new(
                false,
                AdCsCesOutcomeKind.ValidationFailure,
                "Configured AD CS CES Endpoint URL is invalid or does not use HTTPS.");
        }

        string effectiveTemplate = !string.IsNullOrWhiteSpace(templateOverride)
            ? templateOverride.Trim()
            : config.CertificateTemplate.Trim();

        if (string.IsNullOrWhiteSpace(effectiveTemplate))
        {
            return new(
                false,
                AdCsCesOutcomeKind.ValidationFailure,
                "A Certificate Template name is required to submit to AD CS CES.");
        }

        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
            .FirstOrDefaultAsync(p => p.Id == pendingEnrollmentId, cancellationToken);

        if (pending == null)
        {
            return new(false, AdCsCesOutcomeKind.ValidationFailure, "Pending CA enrolment request was not found.");
        }

        if (pending.Status == PendingCaEnrollmentStatus.Activated || pending.Status == PendingCaEnrollmentStatus.Cancelled)
        {
            return new(false, AdCsCesOutcomeKind.ValidationFailure, $"Pending CA enrolment request is already in state '{pending.Status}'.");
        }
        if (!string.IsNullOrWhiteSpace(pending.ReceivedIssuerCertificatePem) && !forceResubmit)
        {
            return new(
                false,
                AdCsCesOutcomeKind.IssuedAwaitingChainAnchor,
                "A signed CA certificate has already been received for this request. Supply the missing parent/root chain or complete validation manually instead of resubmitting the CSR.",
                pending.UpstreamRequestId,
                pending.UpstreamErrorCode,
                null,
                pending);
        }

        if (pending.Status == PendingCaEnrollmentStatus.SubmissionUncertain && !forceResubmit)
        {
            return new(
                false,
                AdCsCesOutcomeKind.SubmissionUncertain,
                "The previous submission to AD CS CES had an uncertain outcome (timeout or connection drop after sending). Reconcile by querying the Request ID from the parent CA, upload the signed certificate manually, or explicitly choose Force Resubmit.",
                pending.UpstreamRequestId,
                pending.UpstreamErrorCode,
                 null,
                pending);
        }

        if (pending.Status == PendingCaEnrollmentStatus.AwaitingApproval && !forceResubmit)
        {
            return new(
                false,
                AdCsCesOutcomeKind.PendingApproval,
                $"Request #{pending.UpstreamRequestId} is already awaiting approval on the parent CA. Use 'Check Pending Status' to query its status instead of resubmitting.",
                pending.UpstreamRequestId,
                null,
                null,
                pending);
        }

        var (credOk, credErr, username, password, clientKeyPem) = ResolveConnectorCredentials(config, oneTimePasswordOverride);
        if (!credOk)
        {
            return new(false, AdCsCesOutcomeKind.AuthenticationFailure, credErr ?? "Connector credentials are missing.");
        }

        string messageId = $"urn:uuid:{Guid.NewGuid():D}";
        string soapEnvelope = BuildWstepIssueSoapEnvelope(
            endpointUri.ToString(),
            messageId,
            pending.CsrPem,
            effectiveTemplate,
            config.AuthenticationMode,
            username,
            password);

        pending.UpstreamEndpointUrl = endpointUri.ToString();
        pending.UpstreamTemplateName = effectiveTemplate;
        pending.LastMessageId = messageId;
        pending.LastSubmittedAtUtc = DateTimeOffset.UtcNow;
        // Persist a crash-safe uncertain state before transmission. A definitive response or
        // pre-send transport failure will replace it; process/network loss after send will not
        // leave the request looking safe to resubmit.
        pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
        pending.LastOutcomeCategory = "Submitting";
        pending.StatusDetailMessage =
            $"Submitting to AD CS CES (MessageID {messageId}). If the process stops before a response is recorded, reconcile with the parent CA before retrying.";
        await db.SaveChangesAsync(cancellationToken);

        return await SendAndProcessWstepRequestAsync(
            db,
            pending,
            config,
            endpointUri,
            clientKeyPem,
            soapEnvelope,
            isInitialIssueSubmission: true,
            cancellationToken);
    }

    /// <summary>
    /// Queries the status of a pending (or uncertain) AD CS CES request using [MS-WSTEP] QueryTokenStatus and wstep:RequestID.
    /// </summary>
    public async Task<AdCsCesOperationResult> QueryPendingStatusAsync(
        int pendingEnrollmentId,
        string? explicitRequestId = null,
        string? oneTimePasswordOverride = null,
        CancellationToken cancellationToken = default)
    {
        AdCsCesConnectorConfig config = await GetConfigAsync(cancellationToken);
        if (!config.IsEnabled)
        {
            return new(
                false,
                AdCsCesOutcomeKind.ValidationFailure,
                "The Microsoft AD CS CES connector is disabled.");
        }

        if (!Uri.TryCreate(config.EndpointUrl, UriKind.Absolute, out Uri? endpointUri)
            || !string.Equals(endpointUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new(
                false,
                AdCsCesOutcomeKind.ValidationFailure,
                "Configured AD CS CES Endpoint URL is invalid or does not use HTTPS.");
        }

        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        PendingCaEnrollmentRecord? pending = await db.PendingCaEnrollments
            .FirstOrDefaultAsync(p => p.Id == pendingEnrollmentId, cancellationToken);

        if (pending == null)
        {
            return new(false, AdCsCesOutcomeKind.ValidationFailure, "Pending CA enrolment request was not found.");
        }

        string? requestIdToQuery = !string.IsNullOrWhiteSpace(explicitRequestId)
            ? explicitRequestId.Trim()
            : pending.UpstreamRequestId?.Trim();

        if (string.IsNullOrWhiteSpace(requestIdToQuery))
        {
            return new(
                false,
                AdCsCesOutcomeKind.ValidationFailure,
                "An upstream AD CS Request ID is required to query status. Enter the Request ID from the Certification Authority console or complete enrolment manually.");
        }

        var (credOk, credErr, username, password, clientKeyPem) = ResolveConnectorCredentials(config, oneTimePasswordOverride);
        if (!credOk)
        {
            return new(false, AdCsCesOutcomeKind.AuthenticationFailure, credErr ?? "Connector credentials are missing.");
        }

        string messageId = $"urn:uuid:{Guid.NewGuid():D}";
        string soapEnvelope = BuildWstepQueryTokenStatusSoapEnvelope(
            endpointUri.ToString(),
            messageId,
            requestIdToQuery,
            config.AuthenticationMode,
            username,
            password);

        pending.UpstreamRequestId = requestIdToQuery;
        pending.LastMessageId = messageId;
        pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
        if (pending.Status == PendingCaEnrollmentStatus.AwaitingSubmission)
        {
            pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
        }
        await db.SaveChangesAsync(cancellationToken);

        return await SendAndProcessWstepRequestAsync(
            db,
            pending,
            config,
            endpointUri,
            clientKeyPem,
            soapEnvelope,
            isInitialIssueSubmission: false,
            cancellationToken);
    }

    private async Task<AdCsCesOperationResult> SendAndProcessWstepRequestAsync(
        CertRoboDbContext db,
        PendingCaEnrollmentRecord pending,
        AdCsCesConnectorConfig config,
        Uri endpointUri,
        string? clientPrivateKeyPem,
        string soapEnvelope,
        bool isInitialIssueSubmission,
        CancellationToken cancellationToken)
    {
        TimeSpan timeout = TimeSpan.FromSeconds(Math.Clamp(config.RequestTimeoutSeconds, 5, 120));
        AdCsCesTransportOptions transportOptions = new(
            endpointUri,
            config.AuthenticationMode,
            config.CustomServerTlsTrustPem,
            config.ClientCertificatePem,
            clientPrivateKeyPem,
            timeout);

        using HttpMessageHandler handler = _handlerFactory(transportOptions);
        using HttpClient httpClient = new(handler, disposeHandler: false)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };

        using TrackingSoapContent content = new(soapEnvelope, WstepActionUri);
        using HttpRequestMessage request = new(HttpMethod.Post, endpointUri)
        {
            Content = content
        };

        using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        HttpResponseMessage response;
        string responseBody;
        bool responseOversized;
        try
        {
            response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token);
            (responseOversized, responseBody) = await ReadBoundedResponseBodyAsync(
                response.Content,
                MaxCesResponseBytes,
                timeoutCts.Token);
        }
        catch (AuthenticationException ex)
        {
            string msg = $"TLS certificate validation failed when connecting to AD CS CES endpoint '{endpointUri.Host}': {SanitizeDiagnosticMessage(ex.Message)}";
            SetFailureStatusForOperation(pending, isInitialIssueSubmission);
            pending.LastOutcomeCategory = "TlsOrTrustFailure";
            pending.StatusDetailMessage = msg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return new(false, AdCsCesOutcomeKind.TlsOrTrustFailure, msg, pending.UpstreamRequestId, null, null, pending);
        }
        catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException authEx)
        {
            string msg = $"TLS certificate validation failed when connecting to AD CS CES endpoint '{endpointUri.Host}': {SanitizeDiagnosticMessage(authEx.Message)}";
            SetFailureStatusForOperation(pending, isInitialIssueSubmission);
            pending.LastOutcomeCategory = "TlsOrTrustFailure";
            pending.StatusDetailMessage = msg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return new(false, AdCsCesOutcomeKind.TlsOrTrustFailure, msg, pending.UpstreamRequestId, null, null, pending);
        }
        catch (HttpRequestException ex) when (IsPreSendConnectionError(ex, content.WasWrittenToStream))
        {
            string msg = $"Could not connect to AD CS CES endpoint '{endpointUri}': {SanitizeDiagnosticMessage(ex.Message)}";
            SetFailureStatusForOperation(pending, isInitialIssueSubmission);
            pending.LastOutcomeCategory = "TransportFailure";
            pending.StatusDetailMessage = msg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return new(false, AdCsCesOutcomeKind.TransportFailure, msg, pending.UpstreamRequestId, null, null, pending);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            if (isInitialIssueSubmission && content.WasWrittenToStream)
            {
                string uncertainMsg =
                    $"AD CS CES submission timed out after {timeout.TotalSeconds:0}s following request transmission (MessageID {pending.LastMessageId}). " +
                    "The parent CA may have accepted the request. Check the parent CA for a Request ID and reconcile with 'Query Status by Request ID', or complete manually.";
                pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
                pending.LastOutcomeCategory = "SubmissionUncertain";
                pending.StatusDetailMessage = uncertainMsg;
                pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                await db.SaveChangesAsync(cancellationToken);
                return new(false, AdCsCesOutcomeKind.SubmissionUncertain, uncertainMsg, pending.UpstreamRequestId, null, null, pending);
            }

            string timeoutMsg = $"AD CS CES status query timed out after {timeout.TotalSeconds:0}s.";
            pending.LastOutcomeCategory = "TransportFailure";
            pending.StatusDetailMessage = timeoutMsg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return new(false, AdCsCesOutcomeKind.TransportFailure, timeoutMsg, pending.UpstreamRequestId, null, null, pending);
        }
        catch (Exception ex)
        {
            if (isInitialIssueSubmission && content.WasWrittenToStream)
            {
                string uncertainMsg =
                    $"Network connection dropped after sending the enrolment request to AD CS CES ({SanitizeDiagnosticMessage(ex.Message)}). " +
                    "The parent CA may have accepted the request. Reconcile using the Request ID from the parent CA or complete manually.";
                pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
                pending.LastOutcomeCategory = "SubmissionUncertain";
                pending.StatusDetailMessage = uncertainMsg;
                pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                await db.SaveChangesAsync(cancellationToken);
                return new(false, AdCsCesOutcomeKind.SubmissionUncertain, uncertainMsg, pending.UpstreamRequestId, null, null, pending);
            }

            string errMsg = $"Transport error communicating with AD CS CES: {SanitizeDiagnosticMessage(ex.Message)}";
            SetFailureStatusForOperation(pending, isInitialIssueSubmission);
            pending.LastOutcomeCategory = "TransportFailure";
            pending.StatusDetailMessage = errMsg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return new(false, AdCsCesOutcomeKind.TransportFailure, errMsg, pending.UpstreamRequestId, null, null, pending);
        }

        using (response)
        {
            int statusCode = (int)response.StatusCode;

            // Reject redirects to prevent credential leakage
            if (statusCode is >= 300 and < 400)
            {
                string redirectMsg =
                    $"AD CS CES endpoint returned HTTP {statusCode} ({response.StatusCode}). Redirects are blocked to prevent credential leakage; configure the direct HTTPS CES service URL.";
                SetFailureStatusForOperation(pending, isInitialIssueSubmission);
                pending.LastOutcomeCategory = "TransportFailure";
                pending.StatusDetailMessage = redirectMsg;
                pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                await db.SaveChangesAsync(cancellationToken);
                return new(false, AdCsCesOutcomeKind.TransportFailure, redirectMsg, pending.UpstreamRequestId, null, null, pending);
            }

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                string authMsg = $"AD CS CES rejected credentials with HTTP {statusCode} ({response.StatusCode}). Verify the connector username/password or client certificate.";
                SetFailureStatusForOperation(pending, isInitialIssueSubmission);
                pending.LastOutcomeCategory = "AuthenticationFailure";
                pending.StatusDetailMessage = authMsg;
                pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                await db.SaveChangesAsync(cancellationToken);
                return new(false, AdCsCesOutcomeKind.AuthenticationFailure, authMsg, pending.UpstreamRequestId, null, null, pending);
            }

            if (responseOversized)
            {
                string oversizedMsg = isInitialIssueSubmission
                    ? $"AD CS CES response exceeded the maximum permitted size of {MaxCesResponseBytes} bytes (HTTP {statusCode}) after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                    : $"AD CS CES response exceeded the maximum permitted size of {MaxCesResponseBytes} bytes (HTTP {statusCode}) when querying pending status.";
                AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                    pending,
                    isInitialIssueSubmission,
                    queryFailureCategory: "ValidationFailure",
                    queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                    oversizedMsg);
                await db.SaveChangesAsync(cancellationToken);
                return new(false, outcomeKind, oversizedMsg, pending.UpstreamRequestId, null, null, pending);
            }

            // Gateway timeouts / 502 / 503 / 504 on an initial Issue request when body is non-SOAP mean outcome is uncertain
            if (isInitialIssueSubmission
                && statusCode is 502 or 503 or 504
                && !responseBody.Contains("Envelope", StringComparison.OrdinalIgnoreCase))
            {
                string gwMsg =
                    $"AD CS CES returned HTTP {statusCode} ({response.StatusCode}) after receiving the request. " +
                    "Whether the parent CA recorded the request is uncertain. Check the parent CA for a Request ID before resubmitting.";
                pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
                pending.LastOutcomeCategory = "SubmissionUncertain";
                pending.StatusDetailMessage = gwMsg;
                pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                await db.SaveChangesAsync(cancellationToken);
                return new(false, AdCsCesOutcomeKind.SubmissionUncertain, gwMsg, pending.UpstreamRequestId, null, null, pending);
            }

            return await ParseAndApplyWstepXmlResponseAsync(
                db,
                pending,
                config,
                response.StatusCode,
                responseBody,
                isInitialIssueSubmission,
                cancellationToken);
        }
    }

    private async Task<AdCsCesOperationResult> ParseAndApplyWstepXmlResponseAsync(
        CertRoboDbContext db,
        PendingCaEnrollmentRecord pending,
        AdCsCesConnectorConfig config,
        HttpStatusCode httpStatus,
        string xmlBody,
        bool isInitialIssueSubmission,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(xmlBody))
        {
            string emptyMsg = isInitialIssueSubmission
                ? $"AD CS CES returned an empty response body (HTTP {(int)httpStatus}) after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : $"AD CS CES returned an empty response body (HTTP {(int)httpStatus}) when querying pending status.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "TransportFailure",
                queryFailureKind: AdCsCesOutcomeKind.TransportFailure,
                emptyMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, emptyMsg, pending.UpstreamRequestId, null, null, pending);
        }

        if (xmlBody.Length > MaxCesResponseBytes)
        {
            string oversizedMsg = isInitialIssueSubmission
                ? $"AD CS CES response exceeded the maximum permitted size of {MaxCesResponseBytes} characters (HTTP {(int)httpStatus}) after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : $"AD CS CES response exceeded the maximum permitted size of {MaxCesResponseBytes} characters (HTTP {(int)httpStatus}) when querying pending status.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "ValidationFailure",
                queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                oversizedMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, oversizedMsg, pending.UpstreamRequestId, null, null, pending);
        }

        XDocument doc;
        try
        {
            XmlReaderSettings xmlSettings = new()
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxCesResponseBytes,
                MaxCharactersFromEntities = 1024
            };
            using StringReader sr = new(xmlBody);
            using XmlReader xmlReader = XmlReader.Create(sr, xmlSettings);
            doc = XDocument.Load(xmlReader);
        }
        catch (Exception)
        {
            string parseMsg = isInitialIssueSubmission
                ? $"AD CS CES returned a non-XML response (HTTP {(int)httpStatus}) after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : $"AD CS CES returned a non-XML response (HTTP {(int)httpStatus}). Ensure the endpoint URL points to the WSTEP service.svc/CES endpoint, not /certsrv.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "TransportFailure",
                queryFailureKind: AdCsCesOutcomeKind.TransportFailure,
                parseMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, parseMsg, pending.UpstreamRequestId, null, null, pending);
        }

        // 1. Check for SOAP Fault
        XElement? faultEl = doc.Descendants(Soap12Ns + "Fault").FirstOrDefault()
            ?? doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Fault");

        if (faultEl != null)
        {
            return await HandleWstepSoapFaultAsync(
                db,
                pending,
                faultEl,
                isInitialIssueSubmission,
                cancellationToken);
        }

        XElement? rstrCollection = doc.Descendants(WstNs + "RequestSecurityTokenResponseCollection").FirstOrDefault();
        if (rstrCollection == null)
        {
            string wrapperMsg = isInitialIssueSubmission
                ? "AD CS CES response did not contain the required WS-Trust RequestSecurityTokenResponseCollection wrapper after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : "AD CS CES response did not contain the required WS-Trust RequestSecurityTokenResponseCollection wrapper.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "ValidationFailure",
                queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                wrapperMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, wrapperMsg, pending.UpstreamRequestId, null, null, pending);
        }

        string? responseAction = doc.Descendants(WsaNs + "Action").FirstOrDefault()?.Value.Trim();
        if (!string.IsNullOrWhiteSpace(responseAction)
            && !responseAction.Contains("/RSTRC/wstep", StringComparison.OrdinalIgnoreCase))
        {
            string actionMsg = isInitialIssueSubmission
                ? $"AD CS CES returned an unexpected WS-Addressing Action '{responseAction}' after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : $"AD CS CES returned an unexpected WS-Addressing Action '{responseAction}'.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "ValidationFailure",
                queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                actionMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, actionMsg, pending.UpstreamRequestId, null, null, pending);
        }

        string? relatesTo = doc.Descendants(WsaNs + "RelatesTo").FirstOrDefault()?.Value.Trim();
        if (!string.IsNullOrWhiteSpace(relatesTo)
            && !string.IsNullOrWhiteSpace(pending.LastMessageId)
            && !relatesTo.Equals(pending.LastMessageId, StringComparison.OrdinalIgnoreCase))
        {
            string correlationMsg = isInitialIssueSubmission
                ? "AD CS CES response WS-Addressing RelatesTo does not match the submitted MessageID. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : "AD CS CES response WS-Addressing RelatesTo does not match the submitted MessageID.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "ValidationFailure",
                queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                correlationMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, correlationMsg, pending.UpstreamRequestId, null, null, pending);
        }

        // 2. Parse RequestSecurityTokenResponse
        XElement? rstrEl = rstrCollection.Elements(WstNs + "RequestSecurityTokenResponse").FirstOrDefault()
            ?? rstrCollection.Elements().FirstOrDefault(e => e.Name.LocalName == "RequestSecurityTokenResponse");

        if (rstrEl == null)
        {
            string unexpectedMsg = isInitialIssueSubmission
                ? "AD CS CES response did not contain a WS-Trust RequestSecurityTokenResponse or SOAP Fault after request transmission. Whether the parent CA recorded the request is uncertain; reconcile with the parent CA Request ID or use Force Resubmit."
                : "AD CS CES response did not contain a WS-Trust RequestSecurityTokenResponse or SOAP Fault.";
            AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "TransportFailure",
                queryFailureKind: AdCsCesOutcomeKind.TransportFailure,
                unexpectedMsg);
            await db.SaveChangesAsync(cancellationToken);
            return new(false, outcomeKind, unexpectedMsg, pending.UpstreamRequestId, null, null, pending);
        }

        string? disposition = rstrEl.Elements().FirstOrDefault(e => e.Name.LocalName == "DispositionMessage")?.Value.Trim();
        string? requestId = rstrEl.Elements().FirstOrDefault(e => e.Name.LocalName == "RequestID")?.Value.Trim();

        if (!string.IsNullOrWhiteSpace(requestId))
        {
            pending.UpstreamRequestId = requestId;
        }

        // Extract all BinarySecurityToken elements from RequestedSecurityToken and RequestSecurityTokenResponse
        List<XElement> bstElements = rstrEl
            .Descendants()
            .Where(e => e.Name.LocalName == "BinarySecurityToken" && !string.IsNullOrWhiteSpace(e.Value))
            .ToList();

        List<X509Certificate2> extractedCerts = [];
        List<string> tokenParseErrors = [];
        try
        {
            if (bstElements.Count > MaxBinarySecurityTokensPerResponse)
            {
                tokenParseErrors.Add($"WSTEP response contained {bstElements.Count} BinarySecurityToken elements, exceeding the maximum permitted count ({MaxBinarySecurityTokensPerResponse}).");
            }
            else
            {
                foreach (XElement bst in bstElements)
                {
                    string? valueType = bst.Attributes()
                        .FirstOrDefault(a => a.Name.LocalName == "ValueType")?.Value;
                    if (!string.IsNullOrWhiteSpace(valueType)
                        && valueType.Contains("PKCS10", StringComparison.OrdinalIgnoreCase))
                    {
                        // MS-WSTEP may echo the original request token in the response.
                        continue;
                    }

                    string? encodingType = bst.Attributes()
                        .FirstOrDefault(a => a.Name.LocalName == "EncodingType")?.Value;
                    if (!string.IsNullOrWhiteSpace(encodingType)
                        && !encodingType.Equals(Base64EncodingTypeUri, StringComparison.OrdinalIgnoreCase))
                    {
                        tokenParseErrors.Add($"Unsupported BinarySecurityToken EncodingType '{encodingType}'.");
                        continue;
                    }

                    string rawB64 = bst.Value.Trim();
                    if (rawB64.Length > CaChainAndConstraintValidator.MaxBundleTextLength)
                    {
                        tokenParseErrors.Add($"WSTEP BinarySecurityToken exceeds the maximum permitted length of {CaChainAndConstraintValidator.MaxBundleTextLength} characters.");
                        continue;
                    }

                    try
                    {
                        List<X509Certificate2> parsedFromToken = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                            null, rawB64, "WSTEP BinarySecurityToken");
                        if (extractedCerts.Count + parsedFromToken.Count > CaChainAndConstraintValidator.MaxCertificatesPerBundle)
                        {
                            foreach (X509Certificate2 c in parsedFromToken) c.Dispose();
                            tokenParseErrors.Add($"WSTEP response exceeds the maximum permitted certificate count ({CaChainAndConstraintValidator.MaxCertificatesPerBundle}).");
                            break;
                        }
                        extractedCerts.AddRange(parsedFromToken);
                    }
                    catch (Exception ex)
                    {
                        tokenParseErrors.Add(SanitizeDiagnosticMessage(ex.Message));
                    }
                }
            }

            extractedCerts = CaChainAndConstraintValidator.DeduplicateCertificates(extractedCerts);

            if (extractedCerts.Count > 0)
            {
                // Issued! Combine extracted certificates with configured DefaultParentChainTrustPem and validate via shared validator
                PendingCaEnrollmentStatus statusBeforeValidation = pending.Status;
                StringBuilder returnedBundlePem = new();
                foreach (X509Certificate2 c in extractedCerts)
                {
                    returnedBundlePem.AppendLine(c.ExportCertificatePem().Trim());
                }

                await db.SaveChangesAsync(cancellationToken);

                CaBundleValidationResult validation = await _caService.ValidateAndStageSignedCaBundleAsync(
                    pending.Id,
                    signedCertBytes: null,
                    signedCertText: returnedBundlePem.ToString(),
                    chainCertBytes: null,
                    chainCertText: config.DefaultParentChainTrustPem,
                    passphraseOverride: null,
                    cancellationToken: cancellationToken);

                PendingCaEnrollmentRecord? refreshed = await _caService.GetPendingEnrollmentByIdAsync(pending.Id, cancellationToken);

                if (validation.IsValid && refreshed != null)
                {
                    string successMsg = string.IsNullOrWhiteSpace(requestId)
                        ? $"AD CS CES issued the subordinate CA certificate ({disposition ?? "Issued"}). Chain and constraints validated; ready for activation."
                        : $"AD CS CES issued the subordinate CA certificate (Request ID #{requestId}, {disposition ?? "Issued"}). Chain and constraints validated; ready for activation.";

                    await UpdatePendingStatusMetadataAsync(
                        pending.Id,
                        PendingCaEnrollmentStatus.ReadyForActivation,
                        "Issued",
                        successMsg,
                        requestId,
                        null,
                        cancellationToken);

                    refreshed = await _caService.GetPendingEnrollmentByIdAsync(pending.Id, cancellationToken);
                    return new(
                        true,
                        AdCsCesOutcomeKind.IssuedReadyForActivation,
                        successMsg,
                        requestId,
                        null,
                        disposition,
                        refreshed);
                }

                // If the signed certificate itself matched the pending key, but the parent/root trust anchor was not included
                // in the CES response or DefaultParentChainTrustPem:
                if (!string.IsNullOrWhiteSpace(validation.ValidatedIssuerCertificatePem))
                {
                    string partialMsg =
                        $"AD CS CES issued the signed CA certificate (Request ID #{requestId ?? "n/a"}), and it has been saved. " +
                        $"To complete validation before activation, supply the parent/root CA trust anchor certificate(s): {validation.ErrorMessage}";

                    await UpdatePendingStatusMetadataAsync(
                        pending.Id,
                        PendingCaEnrollmentStatus.Failed,
                        "IssuedAwaitingChain",
                        partialMsg,
                        requestId,
                        null,
                        cancellationToken);

                    refreshed = await _caService.GetPendingEnrollmentByIdAsync(pending.Id, cancellationToken);
                    return new(
                        false,
                        AdCsCesOutcomeKind.IssuedAwaitingChainAnchor,
                        partialMsg,
                        requestId,
                        null,
                        disposition,
                        refreshed);
                }

                string invalidCertMsg =
                    $"AD CS CES returned a certificate (Request ID #{requestId ?? "n/a"}), but it failed CA validation: {validation.ErrorMessage}";

                PendingCaEnrollmentStatus preservedStatus = isInitialIssueSubmission
                    ? PendingCaEnrollmentStatus.SubmissionUncertain
                    : (statusBeforeValidation is PendingCaEnrollmentStatus.AwaitingApproval or PendingCaEnrollmentStatus.SubmissionUncertain
                        ? statusBeforeValidation
                        : PendingCaEnrollmentStatus.SubmissionUncertain);

                await UpdatePendingStatusMetadataAsync(
                    pending.Id,
                    preservedStatus,
                    "ValidationFailure",
                    invalidCertMsg,
                    requestId,
                    null,
                    cancellationToken);

                refreshed = await _caService.GetPendingEnrollmentByIdAsync(pending.Id, cancellationToken);
                return new(
                    false,
                    AdCsCesOutcomeKind.ValidationFailure,
                    invalidCertMsg,
                    requestId,
                    null,
                    disposition,
                    refreshed);
            }

            if (tokenParseErrors.Count > 0)
            {
                string invalidTokenMsg =
                    "AD CS CES returned certificate token data that could not be parsed safely: "
                    + string.Join(" ", tokenParseErrors.Distinct());
                AdCsCesOutcomeKind outcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                    pending,
                    isInitialIssueSubmission,
                    queryFailureCategory: "ValidationFailure",
                    queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                    invalidTokenMsg);
                await db.SaveChangesAsync(cancellationToken);
                return new(
                    false,
                    outcomeKind,
                    invalidTokenMsg,
                    requestId,
                    null,
                    disposition,
                    pending);
            }

            // No certificate in response -> check if pended (SecurityTokenReference or pending DispositionMessage)
            bool hasSecurityTokenRef = rstrEl.Descendants().Any(e => e.Name.LocalName == "SecurityTokenReference");
            bool dispositionIndicatesPending = !string.IsNullOrWhiteSpace(disposition)
                && (disposition.Contains("Submission", StringComparison.OrdinalIgnoreCase)
                    || disposition.Contains("Pending", StringComparison.OrdinalIgnoreCase));

            if (hasSecurityTokenRef || dispositionIndicatesPending || !string.IsNullOrWhiteSpace(requestId))
            {
                string pendingMsg = !string.IsNullOrWhiteSpace(requestId)
                    ? $"Request #{requestId} is pending approval on the parent AD CS CA (Disposition: '{disposition ?? "Taken Under Submission"}'). Approve the request on the parent CA and click 'Check Pending Status', or upload the signed certificate manually."
                    : $"Request was pended by the parent AD CS CA (Disposition: '{disposition ?? "Taken Under Submission"}'), but no Request ID was returned. Obtain the Request ID or signed certificate from the parent CA administrator to complete enrolment.";

                pending.Status = PendingCaEnrollmentStatus.AwaitingApproval;
                pending.LastOutcomeCategory = "Pending";
                pending.StatusDetailMessage = pendingMsg;
                pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
                await db.SaveChangesAsync(cancellationToken);

                return new(
                    true,
                    AdCsCesOutcomeKind.PendingApproval,
                    pendingMsg,
                    requestId,
                    null,
                    disposition,
                    pending);
            }

            string unknownDispositionMsg = $"AD CS CES returned a response without an issued certificate (Disposition: '{disposition ?? "none"}').";
            AdCsCesOutcomeKind dispOutcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
                pending,
                isInitialIssueSubmission,
                queryFailureCategory: "ValidationFailure",
                queryFailureKind: AdCsCesOutcomeKind.ValidationFailure,
                unknownDispositionMsg);
            await db.SaveChangesAsync(cancellationToken);

            return new(false, dispOutcomeKind, unknownDispositionMsg, requestId, null, disposition, pending);
        }
        finally
        {
            foreach (X509Certificate2 c in extractedCerts) c.Dispose();
        }
    }

    private async Task<AdCsCesOperationResult> HandleWstepSoapFaultAsync(
        CertRoboDbContext db,
        PendingCaEnrollmentRecord pending,
        XElement faultEl,
        bool isInitialIssueSubmission,
        CancellationToken cancellationToken)
    {
        string faultReason = faultEl
            .Descendants()
            .FirstOrDefault(e => e.Name.LocalName == "Text")?.Value.Trim()
            ?? faultEl.Descendants().FirstOrDefault(e => e.Name.LocalName == "faultstring")?.Value.Trim()
            ?? "SOAP Fault returned by AD CS CES.";

        List<string> faultCodes = faultEl
            .Descendants()
            .Where(e => e.Name.LocalName is "Value" or "faultcode")
            .Select(e => e.Value.Trim())
            .ToList();

        XElement? detailEl = faultEl
            .Descendants()
            .FirstOrDefault(e => e.Name.LocalName == "CertificateEnrollmentWSDetail");

        string? errorCode = detailEl?.Elements().FirstOrDefault(e => e.Name.LocalName == "ErrorCode")?.Value.Trim();
        string? requestId = detailEl?.Elements().FirstOrDefault(e => e.Name.LocalName == "RequestID")?.Value.Trim();
        string? invalidReqStr = detailEl?.Elements().FirstOrDefault(e => e.Name.LocalName == "InvalidRequest")?.Value.Trim();
        bool invalidRequest = string.Equals(invalidReqStr, "true", StringComparison.OrdinalIgnoreCase) || invalidReqStr == "1";

        if (!string.IsNullOrWhiteSpace(requestId) && requestId != "-1" && requestId != "0")
        {
            pending.UpstreamRequestId = requestId;
        }

        if (!string.IsNullOrWhiteSpace(errorCode))
        {
            pending.UpstreamErrorCode = errorCode;
        }

        // Check if this is an authentication failure
        bool isAuthFault = faultCodes.Any(c =>
                c.Contains("FailedAuthentication", StringComparison.OrdinalIgnoreCase)
                || c.Contains("InvalidSecurityToken", StringComparison.OrdinalIgnoreCase)
                || c.Contains("SecurityTokenUnavailable", StringComparison.OrdinalIgnoreCase))
            || faultReason.Contains("FailedAuthentication", StringComparison.OrdinalIgnoreCase)
            || (errorCode is "-2147024891" or "0x80070005" && !invalidRequest);

        if (isAuthFault)
        {
            string authFaultMsg = $"AD CS CES authentication failed: {SanitizeDiagnosticMessage(faultReason)}"
                + (!string.IsNullOrWhiteSpace(errorCode) ? $" (ErrorCode: {errorCode})" : "");
            SetFailureStatusForOperation(pending, isInitialIssueSubmission);
            pending.LastOutcomeCategory = "AuthenticationFailure";
            pending.StatusDetailMessage = authFaultMsg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);

            return new(
                false,
                AdCsCesOutcomeKind.AuthenticationFailure,
                authFaultMsg,
                pending.UpstreamRequestId,
                errorCode,
                null,
                pending);
        }

        // Check if the request was denied by the CA or template policy
        bool isDenied = invalidRequest
            || errorCode is "-2146877423" or "0x80094011" // CERTSRV_E_ENROLL_DENIED
                or "-2146877422" or "0x80094012"          // CERTSRV_E_ADMIN_DENIED_REQUEST
                or "-2146877420" or "0x80094014"          // CERTSRV_E_TEMPLATE_DENIED
                or "-2146877410" or "0x8009401E"          // CERTSRV_E_UNSUPPORTED_CERT_TYPE
            || faultReason.Contains("denied", StringComparison.OrdinalIgnoreCase);

        bool isPendingFault = errorCode is "-2146877425" or "0x8009400F" // CERTSRV_E_PENDING
            || faultReason.Contains("pending", StringComparison.OrdinalIgnoreCase)
            || faultReason.Contains("taken under submission", StringComparison.OrdinalIgnoreCase);

        if (isPendingFault)
        {
            string pendingMsg = !string.IsNullOrWhiteSpace(pending.UpstreamRequestId)
                ? $"Request #{pending.UpstreamRequestId} is pending approval on the parent AD CS CA."
                : "The parent AD CS CA reports that the request is pending, but no Request ID was returned. Obtain the Request ID from the CA administrator or complete enrolment manually.";
            pending.Status = PendingCaEnrollmentStatus.AwaitingApproval;
            pending.LastOutcomeCategory = "Pending";
            pending.StatusDetailMessage = pendingMsg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);

            return new(
                true,
                AdCsCesOutcomeKind.PendingApproval,
                pendingMsg,
                pending.UpstreamRequestId,
                errorCode,
                null,
                pending);
        }

        if (isDenied)
        {
            string deniedMsg = $"Parent AD CS CA denied the certificate request: {SanitizeDiagnosticMessage(faultReason)}"
                + (!string.IsNullOrWhiteSpace(pending.UpstreamRequestId) ? $" (Request ID #{pending.UpstreamRequestId})" : "")
                + (!string.IsNullOrWhiteSpace(errorCode) ? $" [ErrorCode: {errorCode}]" : "");

            pending.Status = PendingCaEnrollmentStatus.Failed;
            pending.LastOutcomeCategory = "Denied";
            pending.StatusDetailMessage = deniedMsg;
            pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);

            return new(
                false,
                AdCsCesOutcomeKind.Denied,
                deniedMsg,
                pending.UpstreamRequestId,
                errorCode,
                null,
                pending);
        }

        string genericFaultMsg = $"AD CS CES returned a SOAP fault: {SanitizeDiagnosticMessage(faultReason)}"
            + (!string.IsNullOrWhiteSpace(errorCode) ? $" [ErrorCode: {errorCode}]" : "");

        AdCsCesOutcomeKind faultOutcomeKind = ApplyAmbiguousPostSendOrQueryFailure(
            pending,
            isInitialIssueSubmission,
            queryFailureCategory: "TransportFailure",
            queryFailureKind: AdCsCesOutcomeKind.TransportFailure,
            genericFaultMsg);
        await db.SaveChangesAsync(cancellationToken);

        return new(
            false,
            faultOutcomeKind,
            genericFaultMsg,
            pending.UpstreamRequestId,
            errorCode,
            null,
            pending);
    }

    private static void SetFailureStatusForOperation(
        PendingCaEnrollmentRecord pending,
        bool isInitialIssueSubmission)
    {
        // Used only for pre-send transport/TLS failures or definitive authentication rejections.
        // A failed status query does not change the parent CA's pending request.
        if (isInitialIssueSubmission)
        {
            pending.Status = PendingCaEnrollmentStatus.Failed;
        }
    }

    private static AdCsCesOutcomeKind ApplyAmbiguousPostSendOrQueryFailure(
        PendingCaEnrollmentRecord pending,
        bool isInitialIssueSubmission,
        string queryFailureCategory,
        AdCsCesOutcomeKind queryFailureKind,
        string detailMessage)
    {
        pending.StatusDetailMessage = detailMessage;
        pending.LastCheckedAtUtc = DateTimeOffset.UtcNow;

        if (isInitialIssueSubmission)
        {
            pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
            pending.LastOutcomeCategory = "SubmissionUncertain";
            return AdCsCesOutcomeKind.SubmissionUncertain;
        }

        // For status queries, preserve AwaitingApproval or SubmissionUncertain so an unreadable
        // or failed query response never makes an outstanding request appear safe to resubmit.
        if (pending.Status is not (PendingCaEnrollmentStatus.AwaitingApproval or PendingCaEnrollmentStatus.SubmissionUncertain))
        {
            pending.Status = PendingCaEnrollmentStatus.SubmissionUncertain;
        }
        pending.LastOutcomeCategory = queryFailureCategory;
        return queryFailureKind;
    }

    private async Task UpdatePendingStatusMetadataAsync(
        int pendingId,
        PendingCaEnrollmentStatus status,
        string outcomeCategory,
        string detailMessage,
        string? requestId,
        string? errorCode,
        CancellationToken cancellationToken)
    {
        await using CertRoboDbContext db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        PendingCaEnrollmentRecord? rec = await db.PendingCaEnrollments
            .FirstOrDefaultAsync(p => p.Id == pendingId, cancellationToken);

        if (rec != null)
        {
            rec.Status = status;
            rec.LastOutcomeCategory = outcomeCategory;
            rec.StatusDetailMessage = detailMessage;
            if (!string.IsNullOrWhiteSpace(requestId))
            {
                rec.UpstreamRequestId = requestId;
            }
            if (!string.IsNullOrWhiteSpace(errorCode))
            {
                rec.UpstreamErrorCode = errorCode;
            }
            rec.LastCheckedAtUtc = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    private (bool Succeeded, string? ErrorMessage, string? Username, string? Password, string? ClientPrivateKeyPem)
        ResolveConnectorCredentials(AdCsCesConnectorConfig config, string? oneTimePasswordOverride)
    {
        if (string.Equals(config.AuthenticationMode, "ClientCertificate", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(config.ClientCertificatePem) || string.IsNullOrWhiteSpace(config.ProtectedClientPrivateKeyPem))
            {
                return (false, "Client certificate authentication is selected, but the client certificate or private key is not configured.", null, null, null);
            }

            try
            {
                string clientKey = _credentialProtector.Unprotect(config.ProtectedClientPrivateKeyPem);
                return (true, null, null, null, clientKey);
            }
            catch
            {
                return (false, "Failed to decrypt stored client certificate private key.", null, null, null);
            }
        }

        if (string.IsNullOrWhiteSpace(config.Username))
        {
            return (false, "Username is required for AD CS CES Username/Password authentication.", null, null, null);
        }

        string? resolvedPassword = !string.IsNullOrEmpty(oneTimePasswordOverride)
            ? oneTimePasswordOverride
            : null;

        if (string.IsNullOrEmpty(resolvedPassword) && !string.IsNullOrEmpty(config.ProtectedPassword))
        {
            try
            {
                resolvedPassword = _credentialProtector.Unprotect(config.ProtectedPassword);
            }
            catch
            {
                return (false, "Failed to decrypt stored AD CS CES password. Re-enter and save the connector password.", null, null, null);
            }
        }

        if (string.IsNullOrEmpty(resolvedPassword))
        {
            string? envPass = Environment.GetEnvironmentVariable("CERTROBO_ADCS_CES_PASSWORD");
            if (!string.IsNullOrEmpty(envPass))
            {
                resolvedPassword = envPass;
            }
        }

        if (string.IsNullOrEmpty(resolvedPassword))
        {
            return (false, "Password is required for AD CS CES Username/Password authentication.", null, null, null);
        }

        return (true, null, config.Username.Trim(), resolvedPassword, null);
    }

    public static string BuildWstepIssueSoapEnvelope(
        string endpointUri,
        string messageId,
        string csrPem,
        string certificateTemplate,
        string authenticationMode,
        string? username,
        string? password)
    {
        string base64Csr = string.Concat(
            csrPem
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Where(l => !l.StartsWith("-----", StringComparison.Ordinal))
                .Select(l => l.Trim()));

        string securityHeaderXml = BuildSecurityHeaderXml(authenticationMode, username, password);
        string escapedEndpoint = SecurityElement.Escape(endpointUri);
        string escapedMsgId = SecurityElement.Escape(messageId);
        string escapedTemplate = SecurityElement.Escape(certificateTemplate.Trim());
        string escapedCsr = SecurityElement.Escape(base64Csr);

        // Keep <ac:Value>{escapedTemplate}</ac:Value> without leading/trailing whitespace or newlines
        // because AD CS CES passes the literal ContextItem Value string to ICertRequest2::Submit.
        return
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:a=\"http://www.w3.org/2005/08/addressing\" " +
            "xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" " +
            "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" " +
            "xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" " +
            "xmlns:wstep=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\" " +
            "xmlns:ac=\"http://schemas.xmlsoap.org/ws/2006/12/authorization\">" +
            "<s:Header>" +
            $"<a:Action s:mustUnderstand=\"1\">{WstepActionUri}</a:Action>" +
            $"<a:MessageID>{escapedMsgId}</a:MessageID>" +
            "<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>" +
            $"<a:To s:mustUnderstand=\"1\">{escapedEndpoint}</a:To>" +
            securityHeaderXml +
            "</s:Header>" +
            "<s:Body>" +
            "<wst:RequestSecurityToken>" +
            $"<wst:TokenType>{X509v3TokenTypeUri}</wst:TokenType>" +
            $"<wst:RequestType>{WsTrustIssueUri}</wst:RequestType>" +
            $"<wsse:BinarySecurityToken ValueType=\"{Pkcs10ValueTypeUri}\" EncodingType=\"{Base64EncodingTypeUri}\">{escapedCsr}</wsse:BinarySecurityToken>" +
            $"<ac:AdditionalContext xmlns=\"http://schemas.xmlsoap.org/ws/2006/12/authorization\"><ac:ContextItem Name=\"CertificateTemplate\"><ac:Value>{escapedTemplate}</ac:Value></ac:ContextItem></ac:AdditionalContext>" +
            "</wst:RequestSecurityToken>" +
            "</s:Body>" +
            "</s:Envelope>";
    }

    public static string BuildWstepQueryTokenStatusSoapEnvelope(
        string endpointUri,
        string messageId,
        string requestId,
        string authenticationMode,
        string? username,
        string? password)
    {
        string securityHeaderXml = BuildSecurityHeaderXml(authenticationMode, username, password);
        string escapedEndpoint = SecurityElement.Escape(endpointUri);
        string escapedMsgId = SecurityElement.Escape(messageId);
        string escapedReqId = SecurityElement.Escape(requestId.Trim());

        return
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:a=\"http://www.w3.org/2005/08/addressing\" " +
            "xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" " +
            "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" " +
            "xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" " +
            "xmlns:wstep=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\">" +
            "<s:Header>" +
            $"<a:Action s:mustUnderstand=\"1\">{WstepActionUri}</a:Action>" +
            $"<a:MessageID>{escapedMsgId}</a:MessageID>" +
            "<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>" +
            $"<a:To s:mustUnderstand=\"1\">{escapedEndpoint}</a:To>" +
            securityHeaderXml +
            "</s:Header>" +
            "<s:Body>" +
            "<wst:RequestSecurityToken>" +
            $"<wst:TokenType>{X509v3TokenTypeUri}</wst:TokenType>" +
            $"<wst:RequestType>{WstepQueryTokenStatusUri}</wst:RequestType>" +
            $"<wstep:RequestID>{escapedReqId}</wstep:RequestID>" +
            "</wst:RequestSecurityToken>" +
            "</s:Body>" +
            "</s:Envelope>";
    }

    private static string BuildSecurityHeaderXml(string authenticationMode, string? username, string? password)
    {
        if (string.Equals(authenticationMode, "ClientCertificate", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        string tokenId = $"uuid-{Guid.NewGuid():D}";
        string escapedUser = SecurityElement.Escape(username ?? string.Empty);
        string escapedPass = SecurityElement.Escape(password ?? string.Empty);
        DateTimeOffset created = DateTimeOffset.UtcNow;
        DateTimeOffset expires = created.AddMinutes(5);

        return
            "<wsse:Security s:mustUnderstand=\"1\">" +
            "<u:Timestamp>" +
            $"<u:Created>{created:yyyy-MM-ddTHH:mm:ss.fffZ}</u:Created>" +
            $"<u:Expires>{expires:yyyy-MM-ddTHH:mm:ss.fffZ}</u:Expires>" +
            "</u:Timestamp>" +
            $"<wsse:UsernameToken u:Id=\"{tokenId}\">" +
            $"<wsse:Username>{escapedUser}</wsse:Username>" +
            $"<wsse:Password Type=\"{UsernameTokenPasswordTextUri}\">{escapedPass}</wsse:Password>" +
            "</wsse:UsernameToken>" +
            "</wsse:Security>";
    }

    public static HttpMessageHandler CreateDefaultSocketsHttpHandler(AdCsCesTransportOptions options)
    {
        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            ConnectTimeout = options.Timeout
        };

        if (!string.IsNullOrWhiteSpace(options.CustomServerTlsTrustPem))
        {
            string trustPem = options.CustomServerTlsTrustPem;
            handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, remoteChain, sslPolicyErrors) =>
                ValidateCustomServerTlsCertificate(certificate, remoteChain, sslPolicyErrors, trustPem);
        }

        if (string.Equals(options.AuthenticationMode, "ClientCertificate", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(options.ClientCertificatePem)
            && !string.IsNullOrWhiteSpace(options.ClientPrivateKeyPem))
        {
            using X509Certificate2 pubCert = X509Certificate2.CreateFromPem(options.ClientCertificatePem, options.ClientPrivateKeyPem);
            byte[] pfxBytes = pubCert.Export(X509ContentType.Pkcs12)!;
            X509Certificate2 clientCertWithKey = X509CertificateLoader.LoadPkcs12(pfxBytes, null);
            handler.SslOptions.ClientCertificates = [clientCertWithKey];
        }

        return handler;
    }

    public static bool ValidateCustomServerTlsCertificate(
        X509Certificate? certificate,
        X509Chain? remoteChain,
        SslPolicyErrors sslPolicyErrors,
        string customServerTlsTrustPem)
    {
        if (certificate == null)
        {
            return false;
        }

        // Always enforce peer certificate availability and server hostname matching
        if ((sslPolicyErrors & (SslPolicyErrors.RemoteCertificateNotAvailable | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0)
        {
            return false;
        }

        List<X509Certificate2> customTrustCerts = [];
        try
        {
            customTrustCerts = CaChainAndConstraintValidator.ParseCertificatesFromAnyInput(
                null, customServerTlsTrustPem, "custom TLS trust store");

            if (customTrustCerts.Count == 0)
            {
                return false;
            }

            using X509Certificate2 serverCert = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());

            // 1. Leaf certificate must not be a CA and, if KeyUsage is present, must allow TLS server usage
            X509BasicConstraintsExtension? leafBc = serverCert.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .FirstOrDefault();
            if (leafBc is { CertificateAuthority: true })
            {
                return false;
            }

            X509KeyUsageExtension? leafKu = serverCert.Extensions
                .OfType<X509KeyUsageExtension>()
                .FirstOrDefault();
            if (leafKu != null
                && (leafKu.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyAgreement)) == 0)
            {
                return false;
            }

            // 2. Leaf certificate must permit TLS Server Authentication (1.3.6.1.5.5.7.3.1)
            HashSet<string>? leafEkus = CaChainAndConstraintValidator.ExtractCaEkuConstraintOids(serverCert);
            if (leafEkus == null || !leafEkus.Contains(Models.CertificateProfiles.ServerAuthOid))
            {
                return false;
            }

            // 3. Build chain to an explicitly configured custom root with serverAuth ApplicationPolicy
            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(Models.CertificateProfiles.ServerAuthOid));

            HashSet<string> customRootThumbprints = new(StringComparer.OrdinalIgnoreCase);
            foreach (X509Certificate2 trustCert in customTrustCerts)
            {
                if (CaChainAndConstraintValidator.IsSelfSignedCryptographically(trustCert))
                {
                    chain.ChainPolicy.CustomTrustStore.Add(trustCert);
                    customRootThumbprints.Add(trustCert.GetCertHashString(HashAlgorithmName.SHA256));
                }
                else
                {
                    chain.ChainPolicy.ExtraStore.Add(trustCert);
                }
            }

            if (customRootThumbprints.Count == 0)
            {
                return false;
            }

            if (remoteChain != null)
            {
                for (int i = 1; i < remoteChain.ChainElements.Count; i++)
                {
                    chain.ChainPolicy.ExtraStore.Add(remoteChain.ChainElements[i].Certificate);
                }
            }

            if (!chain.Build(serverCert) || chain.ChainElements.Count < 2)
            {
                return false;
            }

            X509Certificate2 root = chain.ChainElements[^1].Certificate;
            if (!customRootThumbprints.Contains(root.GetCertHashString(HashAlgorithmName.SHA256)))
            {
                return false;
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now < serverCert.NotBefore.ToUniversalTime() || now > serverCert.NotAfter.ToUniversalTime())
            {
                return false;
            }

            // 4. Verify ancestor validity, BasicConstraints, KeyUsage, pathLen, and ancestor EKU/ApplicationPolicy restrictions
            int nonSelfIssuedIntermediatesBelow = 0;
            for (int i = 1; i < chain.ChainElements.Count; i++)
            {
                X509Certificate2 ancestor = chain.ChainElements[i].Certificate;
                if (now < ancestor.NotBefore.ToUniversalTime() || now > ancestor.NotAfter.ToUniversalTime())
                {
                    return false;
                }

                X509BasicConstraintsExtension? ancBc = ancestor.Extensions
                    .OfType<X509BasicConstraintsExtension>()
                    .FirstOrDefault();
                if (ancBc == null || !ancBc.CertificateAuthority)
                {
                    return false;
                }
                if (ancBc.HasPathLengthConstraint && ancBc.PathLengthConstraint < nonSelfIssuedIntermediatesBelow)
                {
                    return false;
                }

                X509KeyUsageExtension? ancKu = ancestor.Extensions
                    .OfType<X509KeyUsageExtension>()
                    .FirstOrDefault();
                if (ancKu != null && (ancKu.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
                {
                    return false;
                }

                HashSet<string>? ancEkus = CaChainAndConstraintValidator.ExtractCaEkuConstraintOids(ancestor);
                if (ancEkus != null
                    && !ancEkus.Contains(Models.CertificateProfiles.ServerAuthOid)
                    && !ancEkus.Contains(CaChainAndConstraintValidator.AnyExtendedKeyUsageOid))
                {
                    return false;
                }

                if (!CaChainAndConstraintValidator.IsSelfIssued(ancestor))
                {
                    nonSelfIssuedIntermediatesBelow++;
                }
            }

            // 5. Verify cryptographic signatures across every link and root self-signature
            for (int i = 0; i < chain.ChainElements.Count - 1; i++)
            {
                if (!CaChainAndConstraintValidator.VerifySignatureCryptographically(
                        chain.ChainElements[i].Certificate,
                        chain.ChainElements[i + 1].Certificate,
                        out _))
                {
                    return false;
                }
            }

            return CaChainAndConstraintValidator.VerifySignatureCryptographically(root, root, out _);
        }
        catch
        {
            return false;
        }
        finally
        {
            foreach (X509Certificate2 c in customTrustCerts) c.Dispose();
        }
    }

    private static bool IsPreSendConnectionError(HttpRequestException ex, bool wasWrittenToStream)
    {
        // Once serialization has begun, a connection failure can occur after CES accepted the
        // request, so it must be treated as uncertain rather than safe to retry automatically.
        return !wasWrittenToStream;
    }

    private static async Task<(bool IsOversized, string Body)> ReadBoundedResponseBodyAsync(
        HttpContent content,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is long contentLength && contentLength > maxBytes)
        {
            return (true, string.Empty);
        }

        await using Stream stream = await content.ReadAsStreamAsync(cancellationToken);
        using MemoryStream buffer = new();
        byte[] chunk = new byte[8192];
        int totalRead = 0;

        while (true)
        {
            int read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
            if (totalRead > maxBytes)
            {
                return (true, string.Empty);
            }

            buffer.Write(chunk, 0, read);
        }

        return (false, Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length));
    }

    private static string SanitizeDiagnosticMessage(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "Unknown error.";
        }
        return message.Length > 500 ? message[..500] : message;
    }

    private sealed class TrackingSoapContent : ByteArrayContent
    {
        public bool WasWrittenToStream { get; private set; }

        public TrackingSoapContent(string soapXml, string actionUri)
            : base(Encoding.UTF8.GetBytes(soapXml))
        {
            Headers.TryAddWithoutValidation(
                "Content-Type",
                $"application/soap+xml; charset=utf-8; action=\"{actionUri}\"");
        }

        protected override Stream CreateContentReadStream(CancellationToken cancellationToken)
        {
            WasWrittenToStream = true;
            return base.CreateContentReadStream(cancellationToken);
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            WasWrittenToStream = true;
            return base.CreateContentReadStreamAsync();
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            WasWrittenToStream = true;
            return base.CreateContentReadStreamAsync(cancellationToken);
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            WasWrittenToStream = true;
            return base.SerializeToStreamAsync(stream, context);
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            WasWrittenToStream = true;
            return base.SerializeToStreamAsync(stream, context, cancellationToken);
        }
    }
}
