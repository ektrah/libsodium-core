using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>Exception tests for the PasswordHash class</summary>
    [TestFixture]
    public class PasswordHashExceptionTest
    {
        [Test]
        public void ScryptHashStringNoPassword()
        {
            const long OPS_LIMIT = 481326;
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                PasswordHash.ScryptHashString(null!, OPS_LIMIT, MEM_LIMIT);
            });
        }

        [Test]
        public void ScryptHashStringBadOpsLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                PasswordHash.ScryptHashString(PASSWORD, 0, MEM_LIMIT);
            });
        }

        [Test]
        public void ScryptHashStringBadMemLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const long OPS_LIMIT = 481326;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                PasswordHash.ScryptHashString(PASSWORD, OPS_LIMIT, 0);
            });
        }

        [Test, Ignore("not implemented")]
        public void ScryptHashStringOutOfMemory()
        {
            //TODO: implement (should work on any testsystem)
            //Note: Int32.MaxValue
            Assert.Throws<System.OutOfMemoryException>(() =>
            {

            });
        }

        [Test]
        public void ScryptHashBinaryNoPassword()
        {
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 32;
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                PasswordHash.ScryptHashBinary(null!, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryNoSalt()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const long OUTPUT_LENGTH = 32;
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                PasswordHash.ScryptHashBinary(PASSWORD, null!, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryWrongSaltLength()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t";
            const long OUTPUT_LENGTH = 32;
            Assert.Throws<SaltOutOfRangeException>(() =>
            {
                PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryBadOpsLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 32;
            const long OPS_LIMIT = 0;
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                PasswordHash.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryBadMemLimit()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 32;
            const long OPS_LIMIT = 481326;
            const int MEM_LIMIT = 0;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                PasswordHash.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
            });
        }

        [Test]
        public void ScryptHashBinaryBadOutputLength()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
            const long OUTPUT_LENGTH = 0;
            const long OPS_LIMIT = 481326;
            const int MEM_LIMIT = 7256678;
            Assert.Throws<System.ArgumentOutOfRangeException>(() =>
            {
                PasswordHash.ScryptHashBinary(PASSWORD, SALT, OPS_LIMIT, MEM_LIMIT, OUTPUT_LENGTH);
            });
        }

        [Test, Ignore("not implemented")]
        public void ScryptHashBinaryOutOfMemory()
        {
            //TODO: implement (should work on any testsystem)
            //Note: Int32.MaxValue
            Assert.Throws<System.OutOfMemoryException>(() =>
            {

            });
        }

        [Test]
        public void ScryptHashStringVerifyNoHash()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                PasswordHash.ScryptHashStringVerify(null!, PASSWORD);
            });
        }

        [Test]
        public void ScryptHashStringVerifyNoPassword()
        {
            const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                var hash = PasswordHash.ScryptHashString(PASSWORD);
                PasswordHash.ScryptHashStringVerify(hash, null!);
            });
        }

    }
}
