using CertRobo.Data;
using System.Text;
using System.Xml.Linq;

namespace CertRobo.Services;

public sealed record LegacyGroupMappingEntry(
    string LegacyAdGroupName,
    IReadOnlyList<string> RawDomainPatterns,
    IReadOnlyList<string> CanonicalDomainPatterns,
    IReadOnlyList<string> InvalidDomainPatterns);

public sealed record LegacySettingsInspectionReport(
    string? LegacyAdcsServer,
    IReadOnlyDictionary<string, string> LegacyTemplates,
    SubjectDefaultsConfig ExtractedDefaults,
    IReadOnlyList<LegacyGroupMappingEntry> GroupMappings)
{
    public string FormatWorksheetText()
    {
        StringBuilder sb = new();
        sb.AppendLine("=== CertRobo Legacy settings.xml Migration Worksheet ===");
        if (!string.IsNullOrWhiteSpace(LegacyAdcsServer))
        {
            sb.AppendLine($"Legacy AD CS Server (retired in standalone mode): {LegacyAdcsServer}");
        }

        sb.AppendLine();
        sb.AppendLine("--- Subject Defaults (<Defaults>) ---");
        sb.AppendLine($"  Country:            {ExtractedDefaults.Country}");
        sb.AppendLine($"  StateOrProvince:    {ExtractedDefaults.StateOrProvince}");
        sb.AppendLine($"  Locality:           {ExtractedDefaults.Locality}");
        sb.AppendLine($"  Organisation:       {ExtractedDefaults.Organisation}");
        sb.AppendLine($"  OrganisationalUnit: {ExtractedDefaults.OrganisationalUnit}");
        sb.AppendLine($"  EmailAddress:       {ExtractedDefaults.EmailAddress}");

        sb.AppendLine();
        sb.AppendLine("--- Legacy AD Group -> Standalone Domain Policy Mapping Review ---");
        sb.AppendLine("NOTE: AD groups are NOT auto-converted into guessed local accounts.");
        sb.AppendLine("Provision local Issuer/Administrator accounts in /admin and assign the reviewed patterns below:");
        foreach (LegacyGroupMappingEntry group in GroupMappings)
        {
            sb.AppendLine($"  * Legacy Group: {group.LegacyAdGroupName}");
            if (group.CanonicalDomainPatterns.Count > 0)
            {
                sb.AppendLine($"    Canonical Domain Patterns: {string.Join(", ", group.CanonicalDomainPatterns)}");
            }
            if (group.InvalidDomainPatterns.Count > 0)
            {
                sb.AppendLine($"    INVALID/REJECTED Patterns: {string.Join(", ", group.InvalidDomainPatterns)}");
            }
        }

        return sb.ToString();
    }
}

/// <summary>
/// Inspects legacy CertRobo settings.xml files to produce a human-reviewable migration worksheet
/// and optionally import X.509 Subject Defaults without auto-creating guessed AD accounts.
/// </summary>
public sealed class LegacySettingsMigrationService(AccountManagementService accountService)
{
    public static LegacySettingsInspectionReport InspectXmlFile(string xmlFilePath)
    {
        if (!File.Exists(xmlFilePath))
        {
            throw new FileNotFoundException($"Legacy settings file not found: {xmlFilePath}", xmlFilePath);
        }

        XDocument doc = XDocument.Load(xmlFilePath);
        return InspectXDocument(doc);
    }

    public static LegacySettingsInspectionReport InspectXDocument(XDocument doc)
    {
        XElement root = doc.Root ?? throw new ArgumentException("XML document does not have a root element.");

        string? server = root.Element("Server")?.Value.Trim();

        Dictionary<string, string> templates = new(StringComparer.OrdinalIgnoreCase);
        foreach (string tplName in new[] { "Template256", "Template384", "Template2048", "Template4096" })
        {
            string? val = root.Element(tplName)?.Value.Trim();
            if (!string.IsNullOrEmpty(val))
            {
                templates[tplName] = val;
            }
        }

        XElement? defaultsEl = root.Element("Defaults");
        SubjectDefaultsConfig defaults = new()
        {
            Country = defaultsEl?.Element("Country")?.Value.Trim().ToUpperInvariant() ?? "US",
            StateOrProvince = defaultsEl?.Element("StateOrProvince")?.Value.Trim() ?? string.Empty,
            Locality = defaultsEl?.Element("Locality")?.Value.Trim() ?? string.Empty,
            Organisation = defaultsEl?.Element("Organisation")?.Value.Trim() ?? string.Empty,
            OrganisationalUnit = defaultsEl?.Element("OrganisationalUnit")?.Value.Trim() ?? string.Empty,
            EmailAddress = defaultsEl?.Element("EmailAddress")?.Value.Trim() ?? string.Empty
        };

        List<LegacyGroupMappingEntry> groups = [];
        XElement? groupsEl = root.Element("Groups");
        if (groupsEl != null)
        {
            foreach (XElement g in groupsEl.Elements("Group"))
            {
                string groupName = g.Element("Name")?.Value.Trim() ?? "(Unnamed Group)";
                List<string> raw = [];
                List<string> canonical = [];
                List<string> invalid = [];

                XElement? domainsEl = g.Element("Domains");
                if (domainsEl != null)
                {
                    foreach (XElement d in domainsEl.Elements("Domain"))
                    {
                        string rawDomain = d.Value.Trim();
                        if (string.IsNullOrEmpty(rawDomain))
                        {
                            continue;
                        }
                        raw.Add(rawDomain);
                        string canon = DomainPolicyEvaluator.CanonicalizeDomainPatternOrIdentity(rawDomain);
                        if (!string.IsNullOrEmpty(canon))
                        {
                            canonical.Add(canon);
                        }
                        else
                        {
                            invalid.Add(rawDomain);
                        }
                    }
                }

                groups.Add(new LegacyGroupMappingEntry(groupName, raw, canonical, invalid));
            }
        }

        return new LegacySettingsInspectionReport(server, templates, defaults, groups);
    }

    public async Task<LegacySettingsInspectionReport> InspectAndOptionallyImportDefaultsAsync(
        string xmlFilePath,
        bool importSubjectDefaults,
        CancellationToken cancellationToken = default)
    {
        LegacySettingsInspectionReport report = InspectXmlFile(xmlFilePath);
        if (importSubjectDefaults)
        {
            await accountService.UpdateSubjectDefaultsAsync(report.ExtractedDefaults, cancellationToken);
        }
        return report;
    }
}
