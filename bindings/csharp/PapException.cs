namespace Pap;

/// <summary>Thrown by any PAP API call that fails at the protocol level.</summary>
public sealed class PapException : Exception
{
    public PapException(string message) : base(message) { }
    public PapException(string message, Exception inner) : base(message, inner) { }
}
