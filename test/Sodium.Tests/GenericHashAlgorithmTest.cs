using System.IO;
using System.Text;
using NUnit.Framework;
using Sodium;

namespace Tests
{
    class GenericHashAlgorithmTest
    {
        /// <summary>BLAKE2b, 32 bytes, with key, from byte array</summary>
        [Test]
        public void ComputeHashFromBytes()
        {
            var expected = Utilities.HexToBinary("8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd");
            var hashStream = new GenericHash.GenericHashAlgorithm("This is a test key", 32);
            var actual = hashStream.ComputeHash(Encoding.UTF8.GetBytes("Adam Caudill"));
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>BLAKE2b, 32 bytes, with key, from empty stream</summary>
        [Test]
        public void ComputeHashFromNullStream()
        {
            var expected = Utilities.HexToBinary("4afd15412c1b940d7cffc9049b9ed413cbaeb626aca2a70c2afbeea7a85bdf8e");
            var stream = Stream.Null;
            var hashStream = new GenericHash.GenericHashAlgorithm("This is a test key", 32);
            var actual = hashStream.ComputeHash(stream);
            CollectionAssert.AreEqual(expected, actual);
        }

        /// <summary>BLAKE2b, 32 bytes, with key, from memory stream</summary>
        [Test]
        public void ComputeHashFromMemoryStream()
        {
            var expected = Utilities.HexToBinary("8866267f985204ae511980704ac85ec4936ee535c37541f342976b2cb3ac62fd");
            var stream = new MemoryStream(Encoding.UTF8.GetBytes("Adam Caudill"));
            var hashStream = new GenericHash.GenericHashAlgorithm("This is a test key", 32);
            var actual = hashStream.ComputeHash(stream);
            CollectionAssert.AreEqual(expected, actual);
        }
    }
}
