using System.Text;
using Sodium;
using NUnit.Framework;
using System.Threading;

namespace Tests
{
    class TestWorker
    {
        public System.Exception exception;

        public void random()
        {
            try
            {
                byte[] bytes;
                bytes = Sodium.SodiumCore.GetRandomBytes(32);
            }
            catch(System.Exception e)
            {
                exception = e;
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
            const int concurrency = 2;
            TestWorker[] workers = new TestWorker[concurrency];
            Thread[] threads = new Thread[concurrency];

            for (int i = 0; i < concurrency; i++)
            {
                workers[i] = new TestWorker();
                threads[i] = new Thread(workers[i].random);
                threads[i].Start();
            }

            for (int i = 0; i < concurrency; i++)
            {
                threads[i].Join();
            }

            for (int i = 0; i < concurrency; i++)
            {
                Assert.IsNull(workers[i].exception);
            }
        }
    }
}
