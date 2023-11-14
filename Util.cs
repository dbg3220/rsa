
using System.Numerics;
using System.Security.Cryptography;

namespace rsa.PrimeGen
{
    public static class Utils
    {
        /// <summary>
        /// A heuristic for checking if a number is prime
        /// </summary>
        /// <param name="value">The number to test</param>
        /// <param name="k">The number of witnesses(default is 10 for this project)</param>
        /// <returns>False if the number is found to be composite, True
        /// if probably prime</returns>
        public static Boolean IsProbablyPrime(this BigInteger value, int k = 10)
        {
            var (r, d) = Factor(value);

            using (var generator = RandomNumberGenerator.Create())
            {
                for (int i = 0; i < k; i++)
                {
                    BigInteger a = randBigInt(2, value - 2);
                    BigInteger x = BigInteger.ModPow(a, d, value);
                    if (x == 1 || x == value - 1)
                    {
                        goto WitnessLoop;
                    }
                    for (int j = 0; j < r - 1; j++)
                    {
                        x = x * x % value;
                        if (x == value - 1)
                        {
                            goto WitnessLoop;
                        }
                    }
                    return false;

                WitnessLoop:;
                }
            }

            return true;
        }

        /// <summary>
        /// Factors value into 2 numbers as such
        /// 
        /// value = 2^r * d + 1
        /// where d must be odd(by factoring out powers of 2 from n - 1)
        /// </summary>
        /// <param name="value">The value to factor</param>
        /// <returns>
        /// A tuple composed of (r, d)
        /// </returns>
        private static Tuple<int, BigInteger> Factor(BigInteger value)
        {
            BigInteger initial = value - 1;
            int r = 0;
            while (initial % 2 == 0)
            {
                initial /= 2;
                r++;
            }
            return new Tuple<int, BigInteger>(r, initial);
        }


        /// <summary>
        /// Computes a random integer in the range specified(inclusive)
        /// 
        /// precondition: low, high are nonnegative integers
        /// precondition: high > low
        /// </summary>
        /// <param name="low">The lower bound of the range</param>
        /// <param name="high">The upper bound of the range</param>
        /// <returns></returns>
        public static BigInteger randBigInt(BigInteger low, BigInteger high)//this works but is not technically random
        {
            BigInteger range = high - low;
            BigInteger randValue;

            do
            {
                int numBytes = computeMinBytes(range);
                byte[] byteArray = new byte[numBytes + 1];
                var generator = RandomNumberGenerator.Create();
                generator.GetBytes(byteArray);
                byteArray[byteArray.Length - 1] = 0;
                randValue = new BigInteger(byteArray) + low;
            } while (randValue <= high);

            return randValue;
        }

        /// <summary>
        /// Computes the minimum number of bytes needed to represent the BigInteger value.
        /// Assuming that the bytes represent unsigned integers.
        /// </summary>
        /// <param name="value">The value to compute off of</param>
        /// <returns>The min number of bytes</returns>
        private static int computeMinBytes(BigInteger value)
        {
            int i = 1;
            while (value > 255)
            {
                value /= 255;
                i++;
            }
            return i;
        }
    }
}