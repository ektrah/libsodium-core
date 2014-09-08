namespace Sodium
{
    /// <summary>A cipher / mac pair.</summary>
  public class Detached
  {
      /// <summary>Initializes a new instance of the <see cref="Detached"/> class.</summary>
    public Detached()
    {
      //do nothing
    }

    /// <summary>Initializes a new instance of the <see cref="Detached"/> class.</summary>
    /// <param name="cipher">The cipher.</param>
    /// <param name="mac">The 16 byte mac.</param>
    public Detached(byte[] cipher, byte[] mac)
    {
      Cipher = cipher;
      Mac = mac;
    }

    /// <summary>Gets or sets the Cipher.</summary>
    public byte[] Cipher { get; set; }

    /// <summary>Gets or sets the MAC.</summary>
    public byte[] Mac { get; set; }
  }
}
