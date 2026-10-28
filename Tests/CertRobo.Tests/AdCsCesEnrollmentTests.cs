using CertRobo.Data;
using CertRobo.Models;
using CertRobo.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace CertRobo.Tests;

public sealed class AdCsCesEnrollmentTests : IDisposable
{
    private const string VaultPassphrase = "CesPendingVaultPass!2026";

    private readonly string _tempRoot;
    private readonly string _dbPath;
    private readonly string _caDir;
    private readonly string _dpDir;
    private readonly ServiceProvider _services;

    public AdCsCesEnrollmentTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"certrobo-ces-{Guid.NewGuid():N}");
        _dbPath = Path.Combine(_tempRoot, "certrobo.db");
        _caDir = Path.Combine(_tempRoot, "ca");
        _dpDir = Path.Combine(_tempRoot, "dp");
        Directory.CreateDirectory(_tempRoot);
        Directory.CreateDirectory(_dpDir);

        ServiceCollection services = new();
        services.AddLogging();
        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(_dpDir));
        services.AddDbContextFactory<CertRoboDbContext>(options =>
            options.UseSqlite($"Data Source={_dbPath}"));
        services.AddSingleton(new CaKeyCustodyOptions
        {
            StorageDirectory = _caDir,
            PassphraseEnvironmentVariable = null,
            ConfiguredPassphrase = VaultPassphrase
        });
        services.AddSingleton<CertificateAuthorityService>();
        _services = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });
        using IServiceScope scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<CertRoboDbContext>()
            .EnsureSchemaUpgradedAsync()
            .GetAwaiter()
            .GetResult();
    }

    [Fact]
    public void WstepIssueEnvelope_UsesSoap12WsAddressingUsernameTokenAndExplicitTemplate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=Issuing CA,O=Tests,C=US",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        string csrPem = request.CreateSigningRequestPem();

        string xml = AdCsCesEnrollmentService.BuildWstepIssueSoapEnvelope(
            "https://ces.example.test/EnrollmentServer/service.svc/CES",
            "urn:uuid:11111111-1111-1111-1111-111111111111",
            csrPem,
            "SubCA",
            "UsernamePassword",
            @"CONTOSO\svc-certrobo",
            "P@ss<&>word");

        XDocument doc = XDocument.Parse(xml);
        XNamespace soap = "http://www.w3.org/2003/05/soap-envelope";
        XNamespace addressing = "http://www.w3.org/2005/08/addressing";
        XNamespace wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        XNamespace wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        XNamespace ac = "http://schemas.xmlsoap.org/ws/2006/12/authorization";

        Assert.Equal(soap + "Envelope", doc.Root!.Name);
        Assert.Equal(AdCsCesEnrollmentService.WstepActionUri, doc.Descendants(addressing + "Action").Single().Value);
        Assert.Equal(@"CONTOSO\svc-certrobo", doc.Descendants(wsse + "Username").Single().Value);
        Assert.Equal("P@ss<&>word", doc.Descendants(wsse + "Password").Single().Value);
        Assert.Single(doc.Descendants(XNamespace.Get(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd") + "Timestamp"));
        Assert.Equal(
            AdCsCesEnrollmentService.UsernameTokenPasswordTextUri,
            doc.Descendants(wsse + "Password").Single().Attribute("Type")!.Value);
        Assert.Equal(AdCsCesEnrollmentService.WsTrustIssueUri, doc.Descendants(wst + "RequestType").Single().Value);
        Assert.Equal(
            AdCsCesEnrollmentService.Pkcs10ValueTypeUri,
            doc.Descendants(wsse + "BinarySecurityToken").Single().Attribute("ValueType")!.Value);
        XElement templateItem = doc.Descendants(ac + "ContextItem")
            .Single(e => (string?)e.Attribute("Name") == "CertificateTemplate");
        Assert.Equal("SubCA", templateItem.Element(ac + "Value")!.Value);
        Assert.DoesNotContain("Authorization: Basic", xml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Name=\"rmd\"", xml, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", xml);
    }

    [Fact]
    public async Task SubmitAndQuery_PersistsPendingRequestIdAcrossRestart()
    {
        ScriptedTransport transport = new(
            _ => SoapResponse(PendingRstr("65", "Taken Under Submission")),
            request =>
            {
                Assert.Contains(AdCsCesEnrollmentService.WstepQueryTokenStatusUri, request.Body);
                Assert.Contains("<wstep:RequestID>65</wstep:RequestID>", request.Body);
                return SoapResponse(PendingRstr("65", "Taken Under Submission"));
            },
            _ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        AdCsCesEnrollmentService ces = CreateCesService(transport);
        await ConfigureUsernamePasswordAsync(ces);
        PendingCaEnrollmentRecord pending = await CreatePendingAsync();

        AdCsCesOperationResult submitted = await ces.SubmitPendingEnrollmentAsync(pending.Id);
        Assert.True(submitted.Succeeded);
        Assert.Equal(AdCsCesOutcomeKind.PendingApproval, submitted.OutcomeKind);
        Assert.Equal("65", submitted.UpstreamRequestId);
        Assert.Contains(
            "action=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep\"",
            transport.Requests[0].ContentType);
        Assert.Contains("UsernameToken", transport.Requests[0].Body);
        Assert.DoesNotContain("Authorization", transport.Requests[0].Headers.Keys);

        // Construct a new connector instance (simulated restart) and continue with persisted RequestID.
        AdCsCesEnrollmentService restartedCes = CreateCesService(transport);
        AdCsCesOperationResult queried = await restartedCes.QueryPendingStatusAsync(pending.Id);
        Assert.True(queried.Succeeded);
        Assert.Equal(AdCsCesOutcomeKind.PendingApproval, queried.OutcomeKind);
        Assert.Equal("65", queried.UpdatedRecord!.UpstreamRequestId);
        Assert.Equal(2, transport.Requests.Count);

        AdCsCesOperationResult failedQuery = await restartedCes.QueryPendingStatusAsync(pending.Id);
        Assert.Equal(AdCsCesOutcomeKind.AuthenticationFailure, failedQuery.OutcomeKind);
        Assert.Equal(PendingCaEnrollmentStatus.AwaitingApproval, failedQuery.UpdatedRecord!.Status);
        Assert.Equal(3, transport.Requests.Count);
    }

    [Fact]
    public async Task IssuedCesResponse_UsesSharedValidator_AndBecomesReadyForActivation()
    {
        PendingCaEnrollmentRecord pending = await CreatePendingAsync();
        using RSA rootKey = RSA.Create(2048);
        using X509Certificate2 rootCert = CreateRoot(rootKey, pathLen: 1);
        using X509Certificate2 issuingCert = SignPending(pending.CsrPem, rootCert, rootKey);

        string bundlePem = issuingCert.ExportCertificatePem() + "\n" + rootCert.ExportCertificatePem();
        string p7bBase64 = Convert.ToBase64String(PkcsBuilder.BuildPkcs7DerFromPemBundle(bundlePem));

        ScriptedTransport transport = new(_ => SoapResponse(IssuedRstr("77", p7bBase64)));
        AdCsCesEnrollmentService ces = CreateCesService(transport);
        await ConfigureUsernamePasswordAsync(ces, rootCert.ExportCertificatePem());

        AdCsCesOperationResult result = await ces.SubmitPendingEnrollmentAsync(pending.Id);
        Assert.True(result.Succeeded, result.SummaryMessage);
        Assert.Equal(AdCsCesOutcomeKind.IssuedReadyForActivation, result.OutcomeKind);
        Assert.Equal(PendingCaEnrollmentStatus.ReadyForActivation, result.UpdatedRecord!.Status);
        Assert.NotNull(CertificateAuthorityService.DeserializeActivationSummary(result.UpdatedRecord));

        CaAuthorityRecord activated = await _services
            .GetRequiredService<CertificateAuthorityService>()
            .ActivatePendingCaEnrollmentAsync(pending.Id);
        Assert.True(activated.IsIntermediate);
        Assert.Contains(rootCert.ExportCertificatePem().Trim(), activated.ChainCertificatesPem);
    }

    [Fact]
    public async Task ConcurrentSubmitAttempts_SendThePersistedCsrOnlyOnce()
    {
        ScriptedTransport transport = new(_ => SoapResponse(PendingRstr("72", "Taken Under Submission")));
        AdCsCesEnrollmentService ces = CreateCesService(transport);
        await ConfigureUsernamePasswordAsync(ces);
        PendingCaEnrollmentRecord pending = await CreatePendingAsync();

        AdCsCesOperationResult[] outcomes = await Task.WhenAll(
            ces.SubmitPendingEnrollmentAsync(pending.Id),
            ces.SubmitPendingEnrollmentAsync(pending.Id));

        Assert.Single(transport.Requests);
        Assert.All(outcomes, outcome => Assert.Equal(AdCsCesOutcomeKind.PendingApproval, outcome.OutcomeKind));
        Assert.Equal(
            pending.CsrPem.Replace("\r", "").Replace("\n", "")
                .Replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .Replace("-----END CERTIFICATE REQUEST-----", ""),
            ExtractBinarySecurityToken(transport.Requests[0].Body));
    }

    [Fact]
    public async Task ConnectorDistinguishesDenialAuthenticationTlsAndAmbiguousSubmission_WithoutBlindRetry()
    {
        // Denial SOAP fault
        PendingCaEnrollmentRecord deniedPending = await CreatePendingAsync();
        ScriptedTransport deniedTransport = new(_ => SoapResponse(
            SoapFault(
                "The requested certificate template is not supported by this CA.",
                "-2146877410",
                "91",
                invalidRequest: true),
            HttpStatusCode.InternalServerError));
        AdCsCesEnrollmentService deniedCes = CreateCesService(deniedTransport);
        await ConfigureUsernamePasswordAsync(deniedCes);
        AdCsCesOperationResult denied = await deniedCes.SubmitPendingEnrollmentAsync(deniedPending.Id);
        Assert.Equal(AdCsCesOutcomeKind.Denied, denied.OutcomeKind);
        Assert.Equal("91", denied.UpstreamRequestId);
        await _services.GetRequiredService<CertificateAuthorityService>()
            .CancelPendingCaEnrollmentAsync(deniedPending.Id);

        // HTTP authentication failure
        PendingCaEnrollmentRecord authPending = await CreatePendingAsync();
        ScriptedTransport authTransport = new(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        AdCsCesEnrollmentService authCes = CreateCesService(authTransport);
        await ConfigureUsernamePasswordAsync(authCes);
        AdCsCesOperationResult auth = await authCes.SubmitPendingEnrollmentAsync(authPending.Id);
        Assert.Equal(AdCsCesOutcomeKind.AuthenticationFailure, auth.OutcomeKind);
        await _services.GetRequiredService<CertificateAuthorityService>()
            .CancelPendingCaEnrollmentAsync(authPending.Id);

        // TLS certificate validation failure
        PendingCaEnrollmentRecord tlsPending = await CreatePendingAsync();
        ScriptedTransport tlsTransport = new(_ =>
            throw new HttpRequestException("TLS failed", new AuthenticationException("Untrusted test root")));
        AdCsCesEnrollmentService tlsCes = CreateCesService(tlsTransport);
        await ConfigureUsernamePasswordAsync(tlsCes);
        AdCsCesOperationResult tls = await tlsCes.SubmitPendingEnrollmentAsync(tlsPending.Id);
        Assert.Equal(AdCsCesOutcomeKind.TlsOrTrustFailure, tls.OutcomeKind);
        Assert.DoesNotContain("Secret1234", tls.SummaryMessage);
        await _services.GetRequiredService<CertificateAuthorityService>()
            .CancelPendingCaEnrollmentAsync(tlsPending.Id);

        // Connection loss after content serialization: uncertain, and a normal retry is blocked.
        PendingCaEnrollmentRecord uncertainPending = await CreatePendingAsync();
        ScriptedTransport uncertainTransport = new(_ =>
            throw new HttpRequestException(HttpRequestError.ConnectionError, "Connection dropped after send"));
        AdCsCesEnrollmentService uncertainCes = CreateCesService(uncertainTransport);
        await ConfigureUsernamePasswordAsync(uncertainCes);
        AdCsCesOperationResult uncertain = await uncertainCes.SubmitPendingEnrollmentAsync(uncertainPending.Id);
        Assert.Equal(AdCsCesOutcomeKind.SubmissionUncertain, uncertain.OutcomeKind);
        int requestCountAfterFailure = uncertainTransport.Requests.Count;

        AdCsCesOperationResult blockedRetry = await uncertainCes.SubmitPendingEnrollmentAsync(uncertainPending.Id);
        Assert.Equal(AdCsCesOutcomeKind.SubmissionUncertain, blockedRetry.OutcomeKind);
        Assert.Equal(requestCountAfterFailure, uncertainTransport.Requests.Count);
    }

    [Fact]
    public async Task ManualCompletionRemainsUsableAfterConnectorFailure()
    {
        PendingCaEnrollmentRecord pending = await CreatePendingAsync();
        ScriptedTransport transport = new(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        AdCsCesEnrollmentService ces = CreateCesService(transport);
        await ConfigureUsernamePasswordAsync(ces);

        AdCsCesOperationResult connectorFailure = await ces.SubmitPendingEnrollmentAsync(pending.Id);
        Assert.Equal(AdCsCesOutcomeKind.SubmissionUncertain, connectorFailure.OutcomeKind);

        using RSA rootKey = RSA.Create(2048);
        using X509Certificate2 rootCert = CreateRoot(rootKey, pathLen: 1);
        using X509Certificate2 issuingCert = SignPending(pending.CsrPem, rootCert, rootKey);
        CaBundleValidationResult manual = await _services
            .GetRequiredService<CertificateAuthorityService>()
            .ValidateAndStageSignedCaBundleAsync(
                pending.Id,
                null,
                issuingCert.ExportCertificatePem(),
                null,
                rootCert.ExportCertificatePem());
        Assert.True(manual.IsValid, manual.ErrorMessage);
    }

    [Fact]
    public async Task IssuedCertificateWithoutChain_IsRetained_AndCannotBeBlindlyResubmitted()
    {
        PendingCaEnrollmentRecord pending = await CreatePendingAsync();
        using RSA rootKey = RSA.Create(2048);
        using X509Certificate2 rootCert = CreateRoot(rootKey, pathLen: 1);
        using X509Certificate2 issuingCert = SignPending(pending.CsrPem, rootCert, rootKey);
        string issuedCertBase64 = Convert.ToBase64String(issuingCert.RawData);

        ScriptedTransport transport = new(_ => SoapResponse(IssuedRstr("88", issuedCertBase64)));
        AdCsCesEnrollmentService ces = CreateCesService(transport);
        await ConfigureUsernamePasswordAsync(ces);

        AdCsCesOperationResult issuedWithoutChain = await ces.SubmitPendingEnrollmentAsync(pending.Id);
        Assert.Equal(AdCsCesOutcomeKind.IssuedAwaitingChainAnchor, issuedWithoutChain.OutcomeKind);
        Assert.NotNull(issuedWithoutChain.UpdatedRecord!.ReceivedIssuerCertificatePem);
        Assert.Single(transport.Requests);

        AdCsCesOperationResult blocked = await ces.SubmitPendingEnrollmentAsync(pending.Id);
        Assert.Equal(AdCsCesOutcomeKind.IssuedAwaitingChainAnchor, blocked.OutcomeKind);
        Assert.Single(transport.Requests);

        CaBundleValidationResult completed = await _services
            .GetRequiredService<CertificateAuthorityService>()
            .ValidateAndStageSignedCaBundleAsync(
                pending.Id,
                signedCertBytes: null,
                signedCertText: null,
                chainCertBytes: null,
                chainCertText: rootCert.ExportCertificatePem());
        Assert.True(completed.IsValid, completed.ErrorMessage);
    }

    private AdCsCesEnrollmentService CreateCesService(ScriptedTransport transport)
    {
        return new AdCsCesEnrollmentService(
            _services.GetRequiredService<IDbContextFactory<CertRoboDbContext>>(),
            _services.GetRequiredService<CertificateAuthorityService>(),
            _services.GetRequiredService<IDataProtectionProvider>(),
            _ => transport.CreateHandler());
    }

    private static async Task ConfigureUsernamePasswordAsync(
        AdCsCesEnrollmentService service,
        string defaultParentChainPem = "")
    {
        var (ok, error, _) = await service.SaveConfigAsync(
            isEnabled: true,
            endpointUrl: "https://ces.example.test/EnrollmentServer/service.svc/CES",
            certificateTemplate: "SubCA",
            authenticationMode: "UsernamePassword",
            username: @"CONTOSO\svc-certrobo",
            newPassword: "ConnectorSecret1234",
            clearSavedPassword: false,
            clientCertificatePem: "",
            newClientPrivateKeyPem: null,
            clearSavedClientKey: false,
            customServerTlsTrustPem: "",
            defaultParentChainTrustPem: defaultParentChainPem,
            requestTimeoutSeconds: 5);
        Assert.True(ok, error);
    }

    private async Task<PendingCaEnrollmentRecord> CreatePendingAsync()
    {
        return await _services.GetRequiredService<CertificateAuthorityService>()
            .CreatePendingCaEnrollmentAsync(
                "CES External Issuing CA",
                "ces-issuing.contoso.com",
                "US",
                "Washington",
                "Redmond",
                "Contoso",
                "PKI",
                CertificateKeyFamily.Ecdsa,
                256,
                VaultPassphrase,
                requestedPathLengthConstraint: 0);
    }

    private static X509Certificate2 CreateRoot(RSA key, int pathLen)
    {
        CertificateRequest rootReq = new(
            "CN=Disposable CES Root CA,O=CertRobo Tests,C=US",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLen, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            true));
        X509SubjectKeyIdentifierExtension ski = new(rootReq.PublicKey, false);
        rootReq.CertificateExtensions.Add(ski);
        rootReq.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(ski));
        return rootReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(2));
    }

    private static X509Certificate2 SignPending(
        string csrPem,
        X509Certificate2 rootCert,
        RSA rootKey)
    {
        CertificateRequest loaded = CertificateRequest.LoadSigningRequestPem(
            csrPem,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        CertificateRequest req = new(loaded.SubjectName, loaded.PublicKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
            true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        req.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                rootCert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single()));
        return req.Create(
            rootCert.SubjectName,
            X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(180),
            RandomNumberGenerator.GetBytes(16));
    }

    private static HttpResponseMessage SoapResponse(string xml, HttpStatusCode status = HttpStatusCode.OK)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(xml, System.Text.Encoding.UTF8, "application/soap+xml")
        };
    }

    private static string PendingRstr(string requestId, string disposition)
    {
        return $$"""
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                        xmlns:wstep="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
                        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <s:Body>
                <wst:RequestSecurityTokenResponseCollection>
                  <wst:RequestSecurityTokenResponse>
                    <wst:TokenType>{{AdCsCesEnrollmentService.X509v3TokenTypeUri}}</wst:TokenType>
                    <wstep:DispositionMessage xml:lang="en-US">{{disposition}}</wstep:DispositionMessage>
                    <wstep:RequestID>{{requestId}}</wstep:RequestID>
                    <wst:RequestedSecurityToken>
                      <wsse:SecurityTokenReference>
                        <wsse:Reference URI="https://ces.example.test/request/{{requestId}}" />
                      </wsse:SecurityTokenReference>
                    </wst:RequestedSecurityToken>
                  </wst:RequestSecurityTokenResponse>
                </wst:RequestSecurityTokenResponseCollection>
              </s:Body>
            </s:Envelope>
            """;
    }

    private static string IssuedRstr(string requestId, string certificateBundleBase64)
    {
        return $$"""
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                        xmlns:wstep="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
                        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <s:Body>
                <wst:RequestSecurityTokenResponseCollection>
                  <wst:RequestSecurityTokenResponse>
                    <wst:TokenType>{{AdCsCesEnrollmentService.X509v3TokenTypeUri}}</wst:TokenType>
                    <wstep:DispositionMessage xml:lang="en-US">Issued</wstep:DispositionMessage>
                    <wstep:RequestID>{{requestId}}</wstep:RequestID>
                    <wst:RequestedSecurityToken>
                      <wsse:BinarySecurityToken ValueType="{{AdCsCesEnrollmentService.X509v3TokenTypeUri}}"
                                                EncodingType="{{AdCsCesEnrollmentService.Base64EncodingTypeUri}}">{{certificateBundleBase64}}</wsse:BinarySecurityToken>
                    </wst:RequestedSecurityToken>
                  </wst:RequestSecurityTokenResponse>
                </wst:RequestSecurityTokenResponseCollection>
              </s:Body>
            </s:Envelope>
            """;
    }

    private static string SoapFault(
        string reason,
        string errorCode,
        string requestId,
        bool invalidRequest)
    {
        return $$"""
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:wstep="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
              <s:Body>
                <s:Fault>
                  <s:Code><s:Value>s:Sender</s:Value></s:Code>
                  <s:Reason><s:Text xml:lang="en-US">{{reason}}</s:Text></s:Reason>
                  <s:Detail>
                    <wstep:CertificateEnrollmentWSDetail>
                      <wstep:ErrorCode>{{errorCode}}</wstep:ErrorCode>
                      <wstep:InvalidRequest>{{invalidRequest.ToString().ToLowerInvariant()}}</wstep:InvalidRequest>
                      <wstep:RequestID>{{requestId}}</wstep:RequestID>
                    </wstep:CertificateEnrollmentWSDetail>
                  </s:Detail>
                </s:Fault>
              </s:Body>
            </s:Envelope>
            """;
    }

    private static string ExtractBinarySecurityToken(string soapXml)
    {
        XDocument doc = XDocument.Parse(soapXml);
        return doc.Descendants()
            .Single(e => e.Name.LocalName == "BinarySecurityToken")
            .Value
            .Trim();
    }

    public void Dispose()
    {
        _services.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_tempRoot, recursive: true);
        }
        catch
        {
        }
    }

    private sealed record CapturedRequest(
        string Body,
        string ContentType,
        IReadOnlyDictionary<string, IEnumerable<string>> Headers);

    private sealed class ScriptedTransport
    {
        private readonly Queue<Func<CapturedRequest, HttpResponseMessage>> _steps;

        public List<CapturedRequest> Requests { get; } = [];

        public ScriptedTransport(params Func<CapturedRequest, HttpResponseMessage>[] steps)
        {
            _steps = new Queue<Func<CapturedRequest, HttpResponseMessage>>(steps);
        }

        public HttpMessageHandler CreateHandler() => new Handler(this);

        private sealed class Handler(ScriptedTransport owner) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                string body = request.Content == null
                    ? string.Empty
                    : await request.Content.ReadAsStringAsync(cancellationToken);
                CapturedRequest captured = new(
                    body,
                    request.Content?.Headers.ContentType?.ToString() ?? string.Empty,
                    request.Headers.ToDictionary(kv => kv.Key, kv => kv.Value));
                owner.Requests.Add(captured);

                if (owner._steps.Count == 0)
                {
                    throw new InvalidOperationException("No scripted response remains.");
                }

                return owner._steps.Dequeue()(captured);
            }
        }
    }
}
