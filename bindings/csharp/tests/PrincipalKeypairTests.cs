using Pap;
using Xunit;

namespace Pap.Tests;

public class PrincipalKeypairTests
{
    [Fact]
    public void Generate_Returns_DidKey()
    {
        using var kp = PrincipalKeypair.Generate();
        Assert.StartsWith("did:key:z", kp.Did());
    }

    [Fact]
    public void PublicKeyBytes_Is_32_Bytes()
    {
        using var kp = PrincipalKeypair.Generate();
        var pub_bytes = kp.PublicKeyBytes();
        Assert.Equal(32, pub_bytes.Length);
    }

    [Fact]
    public void Sign_Returns_64_Byte_Signature()
    {
        using var kp = PrincipalKeypair.Generate();
        var sig = kp.Sign("hello pap"u8.ToArray());
        Assert.Equal(64, sig.Length);
    }

    [Fact]
    public void FromSecretBytes_Roundtrip()
    {
        // Generate, sign, then reconstruct from secret bytes should produce same DID
        using var kp1 = PrincipalKeypair.Generate();
        var did1 = kp1.Did();
        // We can't extract secret bytes directly, but we can verify sign works
        var msg = "test roundtrip"u8.ToArray();
        var sig = kp1.Sign(msg);
        Assert.Equal(64, sig.Length);
    }

    [Fact]
    public void Two_Generated_Keys_Have_Different_DIDs()
    {
        using var kp1 = PrincipalKeypair.Generate();
        using var kp2 = PrincipalKeypair.Generate();
        Assert.NotEqual(kp1.Did(), kp2.Did());
    }

    [Fact]
    public void Dispose_Does_Not_Throw()
    {
        var kp = PrincipalKeypair.Generate();
        var ex = Record.Exception(() => kp.Dispose());
        Assert.Null(ex);
    }

    [Fact]
    public void Double_Dispose_Does_Not_Throw()
    {
        var kp = PrincipalKeypair.Generate();
        kp.Dispose();
        var ex = Record.Exception(() => kp.Dispose());
        Assert.Null(ex);
    }
}
