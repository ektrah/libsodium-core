using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
    /// <summary>Exception tests for the GenericHash class</summary>
    [TestFixture]
    public class GenericHashExceptionTest
    {
        [Test]
        public void GenericHashKeyTooLong()
        {
            const string KEY = "1234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456";
            const int BYTES = 32;
            Assert.Throws<KeyOutOfRangeException>(() => GenericHash.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashKeyTooShort()
        {
            const string KEY = "12345";
            const int BYTES = 32;
            Assert.Throws<KeyOutOfRangeException>(() => GenericHash.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashBytesTooLong()
        {
            const string KEY = "1234567891123456";
            const int BYTES = 128;
            Assert.Throws<BytesOutOfRangeException>(() => GenericHash.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashBytesTooShort()
        {
            const string KEY = "1234567891123456";
            const int BYTES = 12;
            Assert.Throws<BytesOutOfRangeException>(() => GenericHash.Hash("Adam Caudill", KEY, BYTES));
        }

        [Test]
        public void GenericHashSaltPersonalNoMessage()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal(null, KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalNoSalt()
        {
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, null, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalNoPersonal()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string KEY = "1234567891123456";
            Assert.Throws<System.ArgumentNullException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, null));
            });
        }

        [Test]
        public void GenericHashSaltPersonalKeyTooLong()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456123456789112345612345678911234561234567891123456";
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalKeyTooShort()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "12345";
            Assert.Throws<KeyOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalSaltTooLong()
        {
            const string SALT = "5b6b41ed9b343fe05b6b41ed9b343fe05b6b41ed9b343fe05b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<SaltOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalSaltTooShort()
        {
            const string SALT = "5b6b";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<SaltOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalPersonalTooLong()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a5126fb2a37400d2a5126fb2a37400d2a5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<PersonalOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalPersonalTooShort()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126f";
            const string KEY = "1234567891123456";
            Assert.Throws<PersonalOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL));
            });
        }

        [Test]
        public void GenericHashSaltPersonalBytesTooShort()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<BytesOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL, 5));
            });
        }

        [Test]
        public void GenericHashSaltPersonalBytesTooLong()
        {
            const string SALT = "5b6b41ed9b343fe0";
            const string PERSONAL = "5126fb2a37400d2a";
            const string KEY = "1234567891123456";
            Assert.Throws<BytesOutOfRangeException>(() =>
            {
                Utilities.BinaryToHex(GenericHash.HashSaltPersonal("message", KEY, SALT, PERSONAL, 128));
            });
        }
    }
}
