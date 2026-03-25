using Pap;
using Xunit;

namespace Pap.Tests;

public class SafeHandleTests
{
    [Fact]
    public void All_Types_Implement_IDisposable()
    {
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(PrincipalKeypair)));
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(Mandate)));
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(Session)));
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(CapabilityToken)));
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(TransactionReceipt)));
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(AgentAdvertisement)));
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(MarketplaceRegistry)));
    }

    [Fact]
    public void Using_Block_Disposes_PrincipalKeypair()
    {
        var ex = Record.Exception(() =>
        {
            using var kp = PrincipalKeypair.Generate();
            _ = kp.Did(); // use it
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Using_Block_Disposes_Mandate()
    {
        var ex = Record.Exception(() =>
        {
            var (mandate, principal, _) = TestHelpers.MakeSignedMandate();
            using (mandate)
            using (principal)
            {
                _ = mandate.PrincipalDid;
            }
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Using_Block_Disposes_Session()
    {
        var ex = Record.Exception(() =>
        {
            var (session, issuer, _) = TestHelpers.MakeExecutedSession();
            using (session)
            using (issuer)
            {
                _ = session.Id;
            }
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Using_Block_Disposes_CapabilityToken()
    {
        var ex = Record.Exception(() =>
        {
            using var issuer = PrincipalKeypair.Generate();
            using var token = CapabilityToken.Mint(
                "did:key:ztarget", "schema:SearchAction",
                issuer.Did(), TestHelpers.FutureTtl());
            token.Sign(issuer);
            _ = token.ToJson();
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Using_Block_Disposes_Receipt()
    {
        var ex = Record.Exception(() =>
        {
            var (session, issuer, _) = TestHelpers.MakeExecutedSession();
            using (session)
            using (issuer)
            {
                using var receipt = TransactionReceipt.FromSession(
                    session, Array.Empty<string>(), Array.Empty<string>(),
                    "exec", "ret");
                _ = receipt.SessionId;
            }
        });
        Assert.Null(ex);
    }

    [Fact]
    public void Using_Block_Disposes_Advertisement_And_Registry()
    {
        var ex = Record.Exception(() =>
        {
            using var key = PrincipalKeypair.Generate();
            using var ad = new AgentAdvertisement(
                "Agent", "Corp", key.Did(),
                new[] { "schema:SearchAction" },
                Array.Empty<string>(),
                Array.Empty<string>(),
                Array.Empty<string>());
            ad.Sign(key);

            using var registry = new MarketplaceRegistry();
            registry.Register(ad);
            _ = registry.Count;
        });
        Assert.Null(ex);
    }

    [Fact]
    public void GC_Collects_Unreferenced_Handles()
    {
        // Create handles without explicit dispose, force GC, no crash
        var ex = Record.Exception(() =>
        {
            for (int i = 0; i < 100; i++)
            {
                _ = PrincipalKeypair.Generate();
            }
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        });
        Assert.Null(ex);
    }
}
