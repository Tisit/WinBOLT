using WinBolt.Core.Ir;

namespace WinBolt.Core.Passes;

/// <summary>Loads runtime profile data and binds it to a <see cref="BinaryImage"/> (Stage 2).</summary>
public interface IProfileProvider
{
    string Name { get; }

    /// <summary>The fidelity this provider is capable of supplying.</summary>
    ProfileFidelity Fidelity { get; }

    ProfileInfo Load(BinaryImage image, PassContext context);
}
