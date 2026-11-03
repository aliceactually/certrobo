using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CertRobo.Services;

/// <summary>
/// Generates high-entropy human-friendly passphrases by sampling independently and uniformly
/// with replacement from the Electronic Frontier Foundation (EFF) long wordlist (7,776 words).
/// Attribution: EFF large wordlist by Electronic Frontier Foundation, licensed under CC BY 4.0
/// (https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt).
/// </summary>
public static class EffDicewarePassphraseGenerator
{
    public const int ExpectedWordCount = 7776;
    public const int DefaultPassphraseWords = 7;
    public const string DefaultSeparator = "-";
    public const string ExpectedWordlistSha256Hex = "ADDD35536511597A02FA0A9FF1E5284677B8883B83E986E43F15A3DB996B903E";
    public const string EmbeddedResourceLogicalName = "CertRobo.Resources.Passphrases.eff_large_wordlist.txt";

    private static readonly Regex LinePattern = new(
        @"^([1-6]{5})\t([a-z][a-z\-]{1,31})$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Lazy<IReadOnlyList<string>> CachedDefaultWordlist = new(
        () => LoadAndValidateDefaultWordlist(),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public static IReadOnlyList<string> GetValidatedWordlist(string? customWordlistPath = null)
    {
        if (!string.IsNullOrWhiteSpace(customWordlistPath))
        {
            if (!File.Exists(customWordlistPath))
            {
                throw new FileNotFoundException(
                    $"EFF passphrase wordlist file was not found at '{customWordlistPath}'.",
                    customWordlistPath);
            }

            byte[] rawBytes = File.ReadAllBytes(customWordlistPath);
            return ParseAndValidateWordlistBytes(rawBytes, customWordlistPath, verifyOfficialSha256: false);
        }

        return CachedDefaultWordlist.Value;
    }

    public static string GeneratePassphrase(
        int wordCount = DefaultPassphraseWords,
        string separator = DefaultSeparator,
        string? customWordlistPath = null,
        Func<int, int>? uniformIndexSelector = null)
    {
        if (wordCount < DefaultPassphraseWords)
        {
            throw new ArgumentOutOfRangeException(
                nameof(wordCount),
                $"Passphrase word count must be at least {DefaultPassphraseWords} words.");
        }

        if (string.IsNullOrEmpty(separator))
        {
            throw new ArgumentException("A non-empty word separator is required.", nameof(separator));
        }

        IReadOnlyList<string> words = GetValidatedWordlist(customWordlistPath);
        if (words.Count != ExpectedWordCount)
        {
            throw new InvalidOperationException(
                $"EFF wordlist validation failed: expected {ExpectedWordCount} words, found {words.Count}.");
        }

        Func<int, int> selector = uniformIndexSelector ?? RandomNumberGenerator.GetInt32;
        string[] chosen = new string[wordCount];
        for (int i = 0; i < wordCount; i++)
        {
            int idx = selector(words.Count);
            if (idx < 0 || idx >= words.Count)
            {
                throw new InvalidOperationException("Random index selector returned an out-of-range wordlist index.");
            }
            chosen[i] = words[idx];
        }

        return string.Join(separator, chosen);
    }

    public static IReadOnlyList<string> ParseAndValidateWordlistBytes(
        byte[] rawBytes,
        string sourceLabel,
        bool verifyOfficialSha256 = true)
    {
        if (rawBytes is not { Length: > 0 })
        {
            throw new InvalidOperationException($"EFF wordlist '{sourceLabel}' is empty.");
        }

        if (verifyOfficialSha256)
        {
            string actualSha256 = Convert.ToHexString(SHA256.HashData(rawBytes));
            if (!actualSha256.Equals(ExpectedWordlistSha256Hex, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"EFF wordlist '{sourceLabel}' failed SHA-256 integrity verification.");
            }
        }

        string text = Encoding.UTF8.GetString(rawBytes);
        string[] lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != ExpectedWordCount)
        {
            throw new InvalidOperationException(
                $"EFF wordlist '{sourceLabel}' must contain exactly {ExpectedWordCount} entries, but found {lines.Length}.");
        }

        HashSet<string> seenCodes = new(ExpectedWordCount, StringComparer.Ordinal);
        HashSet<string> seenWords = new(ExpectedWordCount, StringComparer.Ordinal);
        List<string> parsedWords = new(ExpectedWordCount);

        foreach (string rawLine in lines)
        {
            Match m = LinePattern.Match(rawLine);
            if (!m.Success)
            {
                throw new InvalidOperationException(
                    $"EFF wordlist '{sourceLabel}' contains a malformed entry line.");
            }

            string diceCode = m.Groups[1].Value;
            string word = m.Groups[2].Value;

            if (!seenCodes.Add(diceCode))
            {
                throw new InvalidOperationException(
                    $"EFF wordlist '{sourceLabel}' contains duplicate dice roll code '{diceCode}'.");
            }

            if (!seenWords.Add(word))
            {
                throw new InvalidOperationException(
                    $"EFF wordlist '{sourceLabel}' contains duplicate word '{word}'.");
            }

            parsedWords.Add(word);
        }

        return parsedWords;
    }

    private static IReadOnlyList<string> LoadAndValidateDefaultWordlist()
    {
        string[] candidatePaths =
        [
            Path.Combine(AppContext.BaseDirectory, "Resources", "Passphrases", "eff_large_wordlist.txt"),
            Path.Combine(Directory.GetCurrentDirectory(), "Resources", "Passphrases", "eff_large_wordlist.txt")
        ];

        foreach (string path in candidatePaths)
        {
            if (File.Exists(path))
            {
                byte[] fileBytes = File.ReadAllBytes(path);
                return ParseAndValidateWordlistBytes(fileBytes, path, verifyOfficialSha256: true);
            }
        }

        Assembly asm = typeof(EffDicewarePassphraseGenerator).Assembly;
        using Stream? resourceStream = asm.GetManifestResourceStream(EmbeddedResourceLogicalName);
        if (resourceStream != null)
        {
            using MemoryStream ms = new();
            resourceStream.CopyTo(ms);
            return ParseAndValidateWordlistBytes(ms.ToArray(), EmbeddedResourceLogicalName, verifyOfficialSha256: true);
        }

        throw new FileNotFoundException(
            "EFF passphrase wordlist 'Resources/Passphrases/eff_large_wordlist.txt' is missing and could not be loaded.");
    }
}
