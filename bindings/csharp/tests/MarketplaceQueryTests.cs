using System.Text.Json;
using Pap;
using Xunit;

namespace Pap.Tests;

public class MarketplaceQueryTests
{
    private static (AgentAdvertisement Ad, PrincipalKeypair Key) MakeSignedAd(
        string name = "Search Agent",
        string[]? capabilities = null,
        string[]? requiresDisclosure = null)
    {
        var key = PrincipalKeypair.Generate();
        var ad = new AgentAdvertisement(
            name,
            "Acme Corp",
            key.Did(),
            capabilities ?? new[] { "schema:SearchAction" },
            new[] { "schema:WebPage" },
            requiresDisclosure ?? Array.Empty<string>(),
            new[] { "schema:SearchResultsPage" });
        ad.Sign(key);
        return (ad, key);
    }

    [Fact]
    public void Create_And_Sign_Advertisement()
    {
        var (ad, key) = MakeSignedAd();
        Assert.Equal("Search Agent", ad.Name);
        key.Dispose();
        ad.Dispose();
    }

    [Fact]
    public void Verify_Advertisement_Signature()
    {
        var (ad, key) = MakeSignedAd();
        // Must not throw
        ad.Verify(key.PublicKeyBytes());
        key.Dispose();
        ad.Dispose();
    }

    [Fact]
    public void Verify_Wrong_Key_Throws()
    {
        var (ad, key) = MakeSignedAd();
        using var wrong = PrincipalKeypair.Generate();
        Assert.Throws<PapException>(() => ad.Verify(wrong.PublicKeyBytes()));
        key.Dispose();
        ad.Dispose();
    }

    [Fact]
    public void SupportsAction_True_For_Matching()
    {
        var (ad, key) = MakeSignedAd();
        Assert.True(ad.SupportsAction("schema:SearchAction"));
        key.Dispose();
        ad.Dispose();
    }

    [Fact]
    public void SupportsAction_False_For_Non_Matching()
    {
        var (ad, key) = MakeSignedAd();
        Assert.False(ad.SupportsAction("schema:PayAction"));
        key.Dispose();
        ad.Dispose();
    }

    [Fact]
    public void Advertisement_Json_Roundtrip()
    {
        var (ad, key) = MakeSignedAd();
        var json = ad.ToJson();

        using var ad2 = AgentAdvertisement.FromJson(json);
        Assert.Equal(ad.Name, ad2.Name);
        Assert.True(ad2.SupportsAction("schema:SearchAction"));

        key.Dispose();
        ad.Dispose();
    }

    [Fact]
    public void Registry_Register_And_QueryByAction()
    {
        using var registry = new MarketplaceRegistry();
        var (searchAd, searchKey) = MakeSignedAd("Search Agent");
        var (payAd, payKey) = MakeSignedAd("Pay Agent",
            capabilities: new[] { "schema:PayAction" });

        registry.Register(searchAd);
        registry.Register(payAd);
        Assert.Equal(2, registry.Count);

        // Query for SearchAction — should find 1
        var searchJson = registry.QueryByAction("schema:SearchAction");
        var searchResults = JsonDocument.Parse(searchJson);
        Assert.Equal(1, searchResults.RootElement.GetArrayLength());
        Assert.Equal("Search Agent",
            searchResults.RootElement[0].GetProperty("name").GetString());

        // Query for PayAction — should find 1
        var payJson = registry.QueryByAction("schema:PayAction");
        var payResults = JsonDocument.Parse(payJson);
        Assert.Equal(1, payResults.RootElement.GetArrayLength());

        // Query for unknown action — should find 0
        var emptyJson = registry.QueryByAction("schema:ReserveAction");
        var emptyResults = JsonDocument.Parse(emptyJson);
        Assert.Equal(0, emptyResults.RootElement.GetArrayLength());

        searchAd.Dispose();
        payAd.Dispose();
        searchKey.Dispose();
        payKey.Dispose();
    }

    [Fact]
    public void Registry_Rejects_Unsigned_Advertisement()
    {
        using var registry = new MarketplaceRegistry();
        using var key = PrincipalKeypair.Generate();
        // Create ad but don't sign it
        using var ad = new AgentAdvertisement(
            "Unsigned Agent", "Corp", key.Did(),
            new[] { "schema:SearchAction" },
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<string>());

        Assert.Throws<PapException>(() => registry.Register(ad));
    }

    [Fact]
    public void Dispose_Releases_All_Handles()
    {
        var (ad, key) = MakeSignedAd();
        var registry = new MarketplaceRegistry();
        registry.Register(ad);

        registry.Dispose();
        ad.Dispose();
        key.Dispose();
        // No crash = clean release
    }
}
