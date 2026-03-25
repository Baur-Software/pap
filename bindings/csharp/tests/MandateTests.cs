using System.Text.Json;
using Pap;
using Xunit;

namespace Pap.Tests;

public class MandateTests
{
    [Fact]
    public void IssueRoot_And_Sign()
    {
        var (mandate, principal, _) = TestHelpers.MakeSignedMandate();
        Assert.Equal(principal.Did(), mandate.PrincipalDid);
        Assert.Equal("did:key:zagent1", mandate.AgentDid);
        mandate.Dispose();
        principal.Dispose();
    }

    [Fact]
    public void Verify_Valid_Signature()
    {
        var (mandate, principal, _) = TestHelpers.MakeSignedMandate();
        // Must not throw
        mandate.Verify(principal.PublicKeyBytes());
        mandate.Dispose();
        principal.Dispose();
    }

    [Fact]
    public void Verify_Wrong_Key_Throws_PapException()
    {
        var (mandate, _, _) = TestHelpers.MakeSignedMandate();
        using var other = PrincipalKeypair.Generate();
        Assert.Throws<PapException>(() => mandate.Verify(other.PublicKeyBytes()));
        mandate.Dispose();
    }

    [Fact]
    public void Json_Roundtrip_Preserves_Fields()
    {
        var (mandate, principal, _) = TestHelpers.MakeSignedMandate();
        var json = mandate.ToJson();

        // Verify it's valid JSON with expected fields
        var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("principal_did", out _));

        using var m2 = Mandate.FromJson(json);
        Assert.Equal(mandate.PrincipalDid, m2.PrincipalDid);
        Assert.Equal(mandate.AgentDid, m2.AgentDid);
        Assert.Equal(mandate.IssuerDid, m2.IssuerDid);

        mandate.Dispose();
        principal.Dispose();
    }

    [Fact]
    public void Hash_Is_Deterministic()
    {
        var (mandate, _, _) = TestHelpers.MakeSignedMandate();
        var hash1 = mandate.Hash();
        var hash2 = mandate.Hash();
        Assert.Equal(hash1, hash2);
        Assert.NotEmpty(hash1);
        mandate.Dispose();
    }

    [Fact]
    public void IsExpired_Future_Returns_False()
    {
        var (mandate, _, _) = TestHelpers.MakeSignedMandate(ttl: TestHelpers.FutureTtl(1));
        Assert.False(mandate.IsExpired());
        mandate.Dispose();
    }

    [Fact]
    public void IsExpired_Past_Returns_True()
    {
        var (mandate, _, _) = TestHelpers.MakeSignedMandate(ttl: TestHelpers.PastTtl());
        Assert.True(mandate.IsExpired());
        mandate.Dispose();
    }

    [Fact]
    public void Delegate_Child_Within_Scope()
    {
        var (parent, principal, _) = TestHelpers.MakeSignedMandate();
        var childScope = Scope.From(("schema:SearchAction", null));
        var ds = DisclosureSet.Empty();

        using var child = parent.Delegate(
            "did:key:zagent2", childScope, ds, TestHelpers.FutureTtl());
        child.Sign(principal);

        Assert.Equal(parent.PrincipalDid, child.PrincipalDid);
        Assert.Equal("did:key:zagent2", child.AgentDid);

        parent.Dispose();
        principal.Dispose();
    }

    [Fact]
    public void Delegate_Exceeds_Scope_Throws()
    {
        var (parent, _, _) = TestHelpers.MakeSignedMandate();
        // Parent has SearchAction only; child asks for PayAction too
        var bigScope = Scope.From(
            ("schema:SearchAction", null),
            ("schema:PayAction", null));
        var ds = DisclosureSet.Empty();

        Assert.Throws<PapException>(() =>
            parent.Delegate("did:key:zagent2", bigScope, ds, TestHelpers.FutureTtl()));
        parent.Dispose();
    }

    [Fact]
    public void DecayState_Active_For_Fresh_Mandate()
    {
        var (mandate, _, _) = TestHelpers.MakeSignedMandate();
        var state = mandate.ComputeDecayState(3600);
        Assert.Equal(DecayState.Active, state);
        mandate.Dispose();
    }

    [Fact]
    public void SyncDecayState_Handles_Expiry_Jump()
    {
        // Create an expired mandate — sync should jump through Degraded to ReadOnly
        var (mandate, _, _) = TestHelpers.MakeSignedMandate(ttl: TestHelpers.PastTtl());
        mandate.SyncDecayState(3600);
        var state = mandate.ComputeDecayState(3600);
        Assert.Equal(DecayState.ReadOnly, state);
        mandate.Dispose();
    }

    [Fact]
    public void Dispose_Releases_Handle()
    {
        var (mandate, principal, _) = TestHelpers.MakeSignedMandate();
        mandate.Dispose();
        principal.Dispose();
        // No crash = success; handle was released cleanly
    }
}
