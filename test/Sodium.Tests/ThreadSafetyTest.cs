using System;
using System.Linq;
using System.Threading;

using NUnit.Framework;

namespace Tests
{
    class TestWorker
    {
        public Exception Exception;

        public void Random()
        {
            try
            {
                var bytes = Sodium.SodiumCore.GetRandomBytes(32);

                //this is mostly to make the compiler happier, as otherwise, bytes is never used
                if (bytes.Count() != 32)
                    throw new Exception("GetRandomCountMismatch");
            }
            catch (Exception ex)
            {
                Exception = ex;
            }
        }
    }

    /// <summary>Tests the thread safety</summary>
    [TestFixture]
    class ThreadSafetyTest
    {
        /// <summary>Does CryptoHash.Hash(string) return the expected value?</summary>
        [Test]
        public void ThreadSafetyRandomTest()
        {
            const int CONCURRENCY = 2;
            var workers = new TestWorker[CONCURRENCY];
            var threads = new Thread[CONCURRENCY];

            for (var i = 0; i < CONCURRENCY; i++)
            {
                workers[i] = new TestWorker();
                threads[i] = new Thread(workers[i].Random);
                threads[i].Start();
            }

            for (var i = 0; i < CONCURRENCY; i++)
            {
                threads[i].Join();
            }

            for (var i = 0; i < CONCURRENCY; i++)
            {
                Assert.IsNull(workers[i].Exception);
            }
        }
    }
}
