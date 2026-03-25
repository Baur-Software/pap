using Pap;
using Xunit;

namespace Pap.Tests;

public class PapExceptionTests
{
    [Fact]
    public void PapException_Is_Exception()
    {
        Assert.True(typeof(PapException).IsSubclassOf(typeof(Exception)));
    }

    [Fact]
    public void PapException_Carries_Message()
    {
        var ex = new PapException("test error");
        Assert.Equal("test error", ex.Message);
    }

    [Fact]
    public void PapException_Wraps_InnerException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new PapException("outer", inner);
        Assert.Equal("outer", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void Invalid_Mandate_Json_Throws_PapException()
    {
        Assert.Throws<PapException>(() => Mandate.FromJson("not valid json"));
    }

    [Fact]
    public void Invalid_Token_Json_Throws_PapException()
    {
        Assert.Throws<PapException>(() => CapabilityToken.FromJson("{\"bad\": true}"));
    }
}
