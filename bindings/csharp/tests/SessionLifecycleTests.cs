using Pap;
using Xunit;

namespace Pap.Tests;

public class SessionLifecycleTests
{
    [Fact]
    public void Initiate_From_Signed_Token()
    {
        using var issuer = PrincipalKeypair.Generate();
        var pubkey = issuer.PublicKeyBytes();

        using var token = CapabilityToken.Mint(
            "did:key:ztarget", "schema:SearchAction", issuer.Did(), TestHelpers.FutureTtl());
        token.Sign(issuer);

        using var session = Session.Initiate(token, "did:key:ztarget", pubkey);
        Assert.Equal(SessionState.Initiated, session.State);
    }

    [Fact]
    public void Full_Lifecycle_Initiated_Open_Executed_Closed()
    {
        using var issuer = PrincipalKeypair.Generate();
        var pubkey = issuer.PublicKeyBytes();

        using var token = CapabilityToken.Mint(
            "did:key:ztarget", "schema:SearchAction", issuer.Did(), TestHelpers.FutureTtl());
        token.Sign(issuer);

        using var session = Session.Initiate(token, "did:key:ztarget", pubkey);
        Assert.Equal(SessionState.Initiated, session.State);

        session.Open("did:key:zinit_sess", "did:key:zrecv_sess");
        Assert.Equal(SessionState.Open, session.State);

        session.Execute();
        Assert.Equal(SessionState.Executed, session.State);

        session.Close();
        Assert.Equal(SessionState.Closed, session.State);
    }

    [Fact]
    public void Session_Has_UUID_Id()
    {
        var (session, _, _) = TestHelpers.MakeExecutedSession();
        var id = session.Id;
        Assert.False(string.IsNullOrEmpty(id));
        // UUID format: 8-4-4-4-12 hex chars
        Assert.Matches(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", id);
        session.Dispose();
    }

    [Fact]
    public void Invalid_State_Transition_Throws()
    {
        using var issuer = PrincipalKeypair.Generate();
        var pubkey = issuer.PublicKeyBytes();

        using var token = CapabilityToken.Mint(
            "did:key:ztarget", "schema:SearchAction", issuer.Did(), TestHelpers.FutureTtl());
        token.Sign(issuer);

        using var session = Session.Initiate(token, "did:key:ztarget", pubkey);
        // Cannot Execute from Initiated state (must Open first)
        Assert.Throws<PapException>(() => session.Execute());
    }

    [Fact]
    public void Token_Json_Roundtrip()
    {
        using var issuer = PrincipalKeypair.Generate();
        using var token = CapabilityToken.Mint(
            "did:key:ztarget", "schema:SearchAction", issuer.Did(), TestHelpers.FutureTtl());
        token.Sign(issuer);

        var json = token.ToJson();
        using var token2 = CapabilityToken.FromJson(json);
        // Roundtrip succeeded — from_json didn't throw
        Assert.NotNull(token2);
    }

    [Fact]
    public void Dispose_Releases_Session_Handle()
    {
        var (session, issuer, _) = TestHelpers.MakeExecutedSession();
        session.Dispose();
        issuer.Dispose();
        // No crash = clean release
    }
}
