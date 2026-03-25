using Pap;

namespace Pap.Tests;

internal static class TestHelpers
{
    /// <summary>RFC 3339 timestamp <paramref name="hours"/> in the future.</summary>
    internal static string FutureTtl(int hours = 1)
        => DateTime.UtcNow.AddHours(hours).ToString("yyyy-MM-ddTHH:mm:ssZ");

    /// <summary>RFC 3339 timestamp 1 second in the past.</summary>
    internal static string PastTtl()
        => DateTime.UtcNow.AddSeconds(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");

    /// <summary>
    /// Create a signed root mandate with a fresh keypair and SearchAction scope.
    /// </summary>
    internal static (Mandate Mandate, PrincipalKeypair Principal, Scope Scope) MakeSignedMandate(
        string? ttl = null)
    {
        var principal = PrincipalKeypair.Generate();
        var scope = Scope.From(("schema:SearchAction", null));
        var ds = DisclosureSet.Empty();
        var mandate = Mandate.IssueRoot(
            principal.Did(), "did:key:zagent1", scope, ds, ttl ?? FutureTtl());
        mandate.Sign(principal);
        return (mandate, principal, scope);
    }

    /// <summary>
    /// Drive a session through Initiated → Open → Executed and return it
    /// along with the issuer keypair and public key bytes.
    /// </summary>
    internal static (Session Session, PrincipalKeypair Issuer, byte[] PubkeyBytes) MakeExecutedSession()
    {
        var issuer = PrincipalKeypair.Generate();
        var pubkey = issuer.PublicKeyBytes();

        var token = CapabilityToken.Mint(
            "did:key:ztarget", "schema:SearchAction", issuer.Did(), FutureTtl());
        token.Sign(issuer);

        var session = Session.Initiate(token, "did:key:ztarget", pubkey);
        session.Open("did:key:zinit_sess", "did:key:zrecv_sess");
        session.Execute();

        return (session, issuer, pubkey);
    }
}
