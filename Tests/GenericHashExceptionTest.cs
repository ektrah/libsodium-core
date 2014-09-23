using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>Exception tests for the GenericHash class</summary>
  [TestFixture]
  public class GenericHashExceptionTest
  {
    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void GenericHashKeyTooLong()
    {
        const string KEY = "1234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456";
        const int BYTES = 32;
        GenericHash.Hash("Adam Caudill", KEY, BYTES);
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void GenericHashKeyTooShort()
    {
        const string KEY = "12345";
        const int BYTES = 32;
        GenericHash.Hash("Adam Caudill", KEY, BYTES);
    }

    [Test]
    [ExpectedException(typeof(BytesOutOfRangeException))]
    public void GenericHashBytesTooLong()
    {
        const string KEY = "1234567891123456";
        const int BYTES = 128;
        GenericHash.Hash("Adam Caudill", KEY, BYTES);
    }

    [Test]
    [ExpectedException(typeof(BytesOutOfRangeException))]
    public void GenericHashBytesTooShort()
    {
        const string KEY = "1234567891123456";
        const int BYTES = 12;
        GenericHash.Hash("Adam Caudill", KEY, BYTES);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void GenericHashSaltPersonalNoMessage()
    {
        const string SALT = "5b6b41ed9b343fe0";
        const string PERSONAL = "5126fb2a37400d2a";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal(null, KEY, SALT, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void GenericHashSaltPersonalNoSalt()
    {
        const string PERSONAL = "5126fb2a37400d2a";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, null, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void GenericHashSaltPersonalNoPersonal()
    {
        const string SALT = "5b6b41ed9b343fe0";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, null));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void GenericHashSaltPersonalKeyTooLong()
    {
        const string SALT = "5b6b41ed9b343fe0";
        const string PERSONAL = "5126fb2a37400d2a";
        const string KEY = "1234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void GenericHashSaltPersonalKeyTooShort()
    {
        const string SALT = "5b6b41ed9b343fe0";
        const string PERSONAL = "5126fb2a37400d2a";
        const string KEY = "12345";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(SaltOutOfRangeException))]
    public void GenericHashSaltPersonalSaltTooLong()
    {
        const string SALT = "5b6b41ed9b343fe05b6b41ed9b343fe05b6b41ed9b343fe05b6b41ed9b343fe0";
        const string PERSONAL = "5126fb2a37400d2a";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(SaltOutOfRangeException))]
    public void GenericHashSaltPersonalSaltTooShort()
    {
        const string SALT = "5b6b";
        const string PERSONAL = "5126fb2a37400d2a";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(PersonalOutOfRangeException))]
    public void GenericHashSaltPersonalPersonalTooLong()
    {
        const string SALT = "5b6b41ed9b343fe0";
        const string PERSONAL = "5126fb2a37400d2a5126fb2a37400d2a5126fb2a37400d2a5126fb2a37400d2a";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
    }

    [Test]
    [ExpectedException(typeof(PersonalOutOfRangeException))]
    public void GenericHashSaltPersonalPersonalTooShort()
    {
        const string SALT = "5b6b41ed9b343fe0";
        const string PERSONAL = "5126f";
        const string KEY = "1234567891123456";
        Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
    }
  }
}
