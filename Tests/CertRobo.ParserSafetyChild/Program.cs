namespace CertRobo.Tests;

public static class ParserSafetyChildEntryPoint
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Expected one parser case ID.");
            return 2;
        }

        string caseId = args[0];
        try
        {
            await ParserSafetyCases.ExecuteIsolatedChildCaseAsync(caseId);
            Console.Out.WriteLine($"CHILD_OK:{caseId}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"CHILD_FAIL:{caseId}:{ex}");
            return 2;
        }
    }
}
