using System.Text.Json;
using Pap;
using Xunit;

namespace Pap.Tests;

public class ReceiptRoundtripTests
{
    [Fact]
    public void FromSession_Creates_Receipt()
    {
        var (session, issuer, _) = TestHelpers.MakeExecutedSession();

        using var receipt = TransactionReceipt.FromSession(
            session,
            Array.Empty<string>(),
            new[] { "operator:search_executed" },
            "schema:SearchAction executed",
            "schema:SearchResult returned");

        Assert.Equal(session.Id, receipt.SessionId);
        Assert.Equal("schema:SearchAction", receipt.Action);
        Assert.Equal(0, receipt.SignatureCount);

        session.Dispose();
        issuer.Dispose();
    }

    [Fact]
    public void CoSign_Adds_Signature()
    {
        var (session, issuer, _) = TestHelpers.MakeExecutedSession();
        using var signer = PrincipalKeypair.Generate();

        using var receipt = TransactionReceipt.FromSession(
            session,
            Array.Empty<string>(),
            Array.Empty<string>(),
            "executed",
            "returned");

        receipt.CoSign(signer);
        Assert.Equal(1, receipt.SignatureCount);

        receipt.CoSign(issuer);
        Assert.Equal(2, receipt.SignatureCount);

        session.Dispose();
        issuer.Dispose();
    }

    [Fact]
    public void VerifyBoth_With_Correct_Keys()
    {
        var (session, _, _) = TestHelpers.MakeExecutedSession();
        using var initKey = PrincipalKeypair.Generate();
        using var recvKey = PrincipalKeypair.Generate();

        using var receipt = TransactionReceipt.FromSession(
            session,
            Array.Empty<string>(),
            new[] { "operator:search_executed" },
            "schema:SearchAction executed",
            "schema:SearchResult returned");

        receipt.CoSign(initKey);
        receipt.CoSign(recvKey);

        // Must not throw
        receipt.VerifyBoth(initKey.PublicKeyBytes(), recvKey.PublicKeyBytes());

        session.Dispose();
    }

    [Fact]
    public void VerifyBoth_Wrong_Key_Throws()
    {
        var (session, _, _) = TestHelpers.MakeExecutedSession();
        using var initKey = PrincipalKeypair.Generate();
        using var recvKey = PrincipalKeypair.Generate();
        using var wrongKey = PrincipalKeypair.Generate();

        using var receipt = TransactionReceipt.FromSession(
            session,
            Array.Empty<string>(),
            Array.Empty<string>(),
            "executed",
            "returned");

        receipt.CoSign(initKey);
        receipt.CoSign(recvKey);

        Assert.Throws<PapException>(() =>
            receipt.VerifyBoth(wrongKey.PublicKeyBytes(), recvKey.PublicKeyBytes()));

        session.Dispose();
    }

    [Fact]
    public void VerifySignature_By_Index()
    {
        var (session, _, _) = TestHelpers.MakeExecutedSession();
        using var key = PrincipalKeypair.Generate();

        using var receipt = TransactionReceipt.FromSession(
            session,
            Array.Empty<string>(),
            Array.Empty<string>(),
            "executed",
            "returned");

        receipt.CoSign(key);
        // Verify index 0
        receipt.VerifySignature(0, key.PublicKeyBytes());

        session.Dispose();
    }

    [Fact]
    public void Json_Roundtrip_Preserves_SessionId_And_Signatures()
    {
        var (session, _, _) = TestHelpers.MakeExecutedSession();
        using var initKey = PrincipalKeypair.Generate();
        using var recvKey = PrincipalKeypair.Generate();

        using var receipt = TransactionReceipt.FromSession(
            session,
            Array.Empty<string>(),
            new[] { "operator:search_executed" },
            "schema:SearchAction executed",
            "schema:SearchResult returned");

        receipt.CoSign(initKey);
        receipt.CoSign(recvKey);

        var json = receipt.ToJson();

        // Verify JSON structure
        var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("session_id", out _));
        Assert.True(doc.RootElement.TryGetProperty("signatures", out var sigs));
        Assert.Equal(2, sigs.GetArrayLength());

        // Deserialize and verify fields
        using var receipt2 = TransactionReceipt.FromJson(json);
        Assert.Equal(receipt.SessionId, receipt2.SessionId);
        Assert.Equal(receipt.Action, receipt2.Action);
        Assert.Equal(2, receipt2.SignatureCount);

        // Verify signatures still valid after round-trip
        receipt2.VerifyBoth(initKey.PublicKeyBytes(), recvKey.PublicKeyBytes());

        session.Dispose();
    }

    [Fact]
    public void Dispose_Releases_Receipt_Handle()
    {
        var (session, issuer, _) = TestHelpers.MakeExecutedSession();
        var receipt = TransactionReceipt.FromSession(
            session, Array.Empty<string>(), Array.Empty<string>(), "exec", "ret");
        receipt.Dispose();
        session.Dispose();
        issuer.Dispose();
        // No crash = clean release
    }
}
