using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  /// <summary>Exception tests for the PasswordHash class</summary>
  [TestFixture]
  public class PasswordHashExceptionTest
  {
    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void ScryptHashStringNoPassword()
    {
        const long OPS_LIMIT = 481326;
        const int MEM_LIMIT = 7256678;
        PasswordHash.ScryptHashString(null, OPS_LIMIT, MEM_LIMIT);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentOutOfRangeException))]
    public void ScryptHashStringBadOpsLimit()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const int MEM_LIMIT = 7256678;
        PasswordHash.ScryptHashString(PASSWORD, 0, MEM_LIMIT);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentOutOfRangeException))]
    public void ScryptHashStringBadMemLimit()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const long OPS_LIMIT = 481326;
        PasswordHash.ScryptHashString(PASSWORD, OPS_LIMIT, 0);
    }
    
    [Test]
    [ExpectedException(typeof(System.OutOfMemoryException))]
    public void ScryptHashStringOutOfMemory()
    {
        //TODO: implement (should work on any testsystem)
        //Note: Int32.MaxValue
        throw new System.OutOfMemoryException();
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void ScryptHashBinaryNoPassword()
    {
        const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
        const long OUTPUT_LENGTH = 32;
        PasswordHash.ScryptHashBinary(null, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void ScryptHashBinaryNoSalt()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const long OUTPUT_LENGTH = 32;
        PasswordHash.ScryptHashBinary(PASSWORD, null, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
    }

    [Test]
    [ExpectedException(typeof(SaltOutOfRangeException))]
    public void ScryptHashBinaryWrongSaltLength()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const string SALT = "qa~t](84z<1t";
        const long OUTPUT_LENGTH = 32;
        PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentOutOfRangeException))]
    public void ScryptHashBinaryBadOpsLimit()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
        const long OUTPUT_LENGTH = 32;
        const long OPS_LIMIT = 0;
        const int MEM_LIMIT = 7256678;
        PasswordHash.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentOutOfRangeException))]
    public void ScryptHashBinaryBadMemLimit()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
        const long OUTPUT_LENGTH = 32;
        const long OPS_LIMIT = 481326;
        const int MEM_LIMIT = 0;
        PasswordHash.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentOutOfRangeException))]
    public void ScryptHashBinaryBadOutputLength()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
        const long OUTPUT_LENGTH = 0;
        const long OPS_LIMIT = 481326;
        const int MEM_LIMIT = 7256678;
        PasswordHash.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
    }

    [Test]
    [ExpectedException(typeof(System.OutOfMemoryException))]
    public void ScryptHashBinaryOutOfMemory()
    {
        //TODO: implement (should work on any testsystem)
        //Note: Int32.MaxValue
        throw new System.OutOfMemoryException();
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void ScryptHashStringVerifyNoHash()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        PasswordHash.ScryptHashStringVerify(null, PASSWORD);
    }

    [Test]
    [ExpectedException(typeof(System.ArgumentNullException))]
    public void ScryptHashStringVerifyNoPassword()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        var hash = PasswordHash.ScryptHashString(PASSWORD);
        PasswordHash.ScryptHashStringVerify(hash, null);
    }

  }
}
