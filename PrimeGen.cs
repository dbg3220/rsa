
using System.Numerics;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Collections.Concurrent;

namespace rsa.PrimeGen
{
    /// <summary>
    /// Contains methods for generating large prime numbers
    /// </summary>
    class PrimeNumberGenerator
    {
        private int bits;

        /// <summary>
        /// Numbers of threads to create to speed up prime number generation
        /// </summary>
        private int numThreads;

        /// <summary>
        /// Creates a prime number generator
        /// </summary>
        /// <param name="bits">The number of bits to use when
        /// generating prime numbers
        /// </param>
        /// <precondition>The bits parameter is a nonnegative multiple of 8</precondition>
        public PrimeNumberGenerator(int bits)
        {
            this.bits = bits;
            numThreads = 1000; // an arbitrary constant
        }

        /// <summary>
        /// Generates prime numbers using threads and writes them to the console
        /// </summary>
        /// <param name="count"></param>
        public void displayNums(int count)
        {
            List<Task> tasks = new List<Task>();
            ConcurrentQueue<BigInteger> resultBox = new ConcurrentQueue<BigInteger>();
            CancellationTokenSource tokenSource = new CancellationTokenSource();
            CancellationToken token = tokenSource.Token;
            for (int i = 0; i < numThreads; i++)
            {
                Task thisTask = Task.Run(() => threadedGetNum(resultBox, bits, token));
                tasks.Add(thisTask);
            }

            int numsGenerated = 0;
            for (; ; )
            {
                if (count == numsGenerated)
                {
                    tokenSource.Cancel();
                    foreach (Task t in tasks)
                    {
                        t.Wait();
                    }
                    tokenSource.Dispose();
                    break;
                }
                if (resultBox.Count > 0)
                {
                    BigInteger num;
                    resultBox.TryDequeue(out num);
                    Console.WriteLine((numsGenerated + 1) + ": " + num);
                    numsGenerated++;
                    if (numsGenerated != count)
                    {
                        Console.WriteLine();
                    }
                }
            }
        }

        /// <summary>
        /// Generate 1 prime number using threads
        /// </summary>
        /// <returns>The prime number that was generated</returns>
        public BigInteger getNum()
        {
            return getNums(1)[0];
        }

        /// <summary>
        /// Generates prime numbers using threads and returns them in an array
        /// </summary>
        /// <param name="count">The amount of prime numbers to generate</param>
        /// <returns>The result as an array of BigIntegers</returns>
        public BigInteger[] getNums(int count)
        {
            //TODO
            return null;
        }

        /// <summary>
        /// Threaded method to continually generate prime numbers and place them
        /// in a queue until the thread is cancelled.
        /// </summary>
        /// <param name="resultBox">The thread safe collection to store the result</param>
        /// <param name="bits">The number of bits to generate the prime number with</param>
        /// <param name="token">The signal used to request cancellation of a thread</param>
        private static void threadedGetNum(ConcurrentQueue<BigInteger> resultBox, int bits, CancellationToken token)
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                for (; ; )
                {
                    BigInteger num;
                    do
                    {
                        if (token.IsCancellationRequested)
                        {
                            return;
                        }
                        byte[] byteArray = new byte[bits / 8 + 1];
                        generator.GetBytes(byteArray);
                        byteArray[byteArray.Length - 1] = 0;
                        num = new BigInteger(byteArray);
                    } while (num % 2 == 0 || !num.IsProbablyPrime());
                    resultBox.Enqueue(num);
                }
            }
        }
    }
}