using System.Collections;
using System.Dynamic;
using System.Numerics;
using rsa.PrimeGen;

namespace rsa.Keys
{
    public class Key
    {
        /// <summary>
        /// The size in bits of the key
        /// </summary>
        private int n;

        /// <summary>
        /// The key
        /// </summary>
        private BigInteger N;

        /// <summary>
        /// Generates a key
        /// </summary>
        /// <param name="n">The bit size of the key</param>
        /// <param name="N">The key</param>
        public Key(int n, BigInteger N)
        {
            this.n = n;
            this.N = N;
        }

        /// <summary>
        /// Getter for the key size, small n
        /// </summary>
        /// <returns>The key size</returns>
        public int getKeysize()
        {
            return n;
        }

        /// <summary>
        /// Getter for the key value, large N
        /// </summary>
        /// <returns>The key size</returns>
        public BigInteger getN()
        {
            return N;
        }

        /// <summary>
        /// Creates a pair of key objects and writes them to the
        /// disc in the current working directory.
        /// </summary>
        /// <param name="keysize">The size in bits of the key pair</param>
        /// <returns>A tuple of the 2 keys created</returns>
        public static Tuple<PublicKey, PrivateKey> generateKeyPair(int keysize)
        {
            int psize = (int)(0.7 * keysize);
            int modulusResult = psize % 8;
            psize -= modulusResult;
            int qsize = keysize - psize;
            PrimeNumberGenerator gen = new PrimeNumberGenerator(psize);
            BigInteger p = gen.getNum();
            PrimeNumberGenerator gen2 = new PrimeNumberGenerator(qsize);
            BigInteger q = gen2.getNum();
            BigInteger N = BigInteger.Multiply(p, q);
            BigInteger totient = BigInteger.Multiply(p - 1, q - 1);
            PrimeNumberGenerator gen3 = new PrimeNumberGenerator(16);
            BigInteger E = gen3.getNum();
            BigInteger D = Utils.modInverse(E, totient);

            PublicKey publicKey = new PublicKey(keysize, N, 16, E);
            PrivateKey privateKey = new PrivateKey(keysize, N, Utils.computeMinBits(D), D);
            return new Tuple<PublicKey, PrivateKey>(publicKey, privateKey);
        }
    }

    public class PublicKey : Key
    {
        const string default_filename = "public.key";

        /// <summary>
        /// The size in bits of the public key
        /// </summary>
        private int e;

        /// <summary>
        /// The public key
        /// </summary>
        private BigInteger E;

        /// <summary>
        /// Generates a public key and writes it to the disc using
        /// 'default_filename'. If a file already exists with that name
        /// it is overwritten.
        /// </summary>
        /// <param name="n">The size in bits of the key</param>
        /// <param name="N">The key</param>
        /// <param name="e">The size in bits of the public key</param>
        /// <param name="E">The public key</param>
        public PublicKey(int n, BigInteger N, int e, BigInteger E) : base(n, N)
        {
            this.e = e;
            this.E = E;
            var base64encodedkey = encodeKeyIn64();
            var json = $"{{\"email\":\"\", \"key\":\"{base64encodedkey}\"}}";
            FileInfo f = new FileInfo(default_filename);
            using (StreamWriter sw = f.CreateText())
            {
                sw.Write(json);
            }
        }

        /// <summary>
        /// Getter for the public portion of the key, large E
        /// </summary>
        /// <returns>The public key</returns>
        public BigInteger getE()
        {
            return E;
        }

        /// <summary>
        /// Generates a key encoded in base64 given the
        /// state of this object
        /// </summary>
        /// <returns>A string in base 64</returns>
        private string encodeKeyIn64()
        {
            List<byte> byteSequence = new List<byte>();
            // the small e value
            byte[] eBytes = BitConverter.GetBytes((int)Math.Ceiling(e / 8.0));
            for (int i = 0; i < 4; i++)
                byteSequence.Add(eBytes[i]);
            // the big E value
            byte[] bigEBytes = E.ToByteArray();
            Array.Reverse(bigEBytes);
            foreach (var b in bigEBytes)
                byteSequence.Add(b);
            // the small n value
            byte[] nBytes = BitConverter.GetBytes((int)Math.Ceiling(getKeysize() / 8.0));
            foreach (var b in nBytes)
                byteSequence.Add(b);
            // the big N value
            byte[] bigNBytes = getN().ToByteArray();
            foreach (var b in bigNBytes)
                byteSequence.Add(b);

            return System.Convert.ToBase64String(byteSequence.ToArray());
        }
    }

    public class PrivateKey : Key
    {
        const string filename = "private.key";

        /// <summary>
        /// The size in bits of the private key
        /// </summary>
        private int d;

        /// <summary>
        /// The private key
        /// </summary>
        private BigInteger D;

        /// <summary>
        /// Generates a private key and writes it to the disc using
        /// 'filename'. If a file already exists with that name
        /// it is overwritten.
        /// </summary>
        /// <param name="n">The size in bits of the key</param>
        /// <param name="N">The key</param>
        /// <param name="d">The size in bits of the private key</param>
        /// <param name="D">The private key</param>
        public PrivateKey(int n, BigInteger N, int d, BigInteger D) : base(n, N)
        {
            this.d = d;
            this.D = D;
            var base64encodedkey = encodeKeyIn64();
            var json = $"{{\"email\":\"\", \"key\":\"{base64encodedkey}\"}}";
            FileInfo f = new FileInfo(filename);
            using (StreamWriter sw = f.CreateText())
            {
                sw.Write(json);
            }
        }

        /// <summary>
        /// Getter for the private portion of the key, large D
        /// </summary>
        /// <returns>The private key</returns>
        public BigInteger getD()
        {
            return D;
        }

        /// <summary>
        /// Generates a key encoded in base64 given the
        /// state of this object
        /// </summary>
        /// <returns>A string in base 64</returns>
        private string encodeKeyIn64()
        {
            List<byte> byteSequence = new List<byte>();
            // the small d value
            byte[] eBytes = BitConverter.GetBytes((int)Math.Ceiling(d / 8.0));
            foreach (var b in eBytes)
                byteSequence.Add(b);
            // the big D value
            byte[] bigEBytes = D.ToByteArray();
            Array.Reverse(bigEBytes);
            foreach (var b in bigEBytes)
                byteSequence.Add(b);
            // the small n value
            byte[] nBytes = BitConverter.GetBytes((int)Math.Ceiling(getKeysize() / 8.0));
            foreach (var b in nBytes)
                byteSequence.Add(b);
            // the big N value
            byte[] bigNBytes = getN().ToByteArray();
            foreach (var b in bigNBytes)
                byteSequence.Add(b);

            return System.Convert.ToBase64String(byteSequence.ToArray());
        }
    }
}