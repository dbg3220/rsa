using System.Collections;
using System.ComponentModel.Design.Serialization;
using System.Dynamic;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;
using rsa.PrimeGen;

namespace rsa.Keys
{
    /// <summary>
    /// Contains static methods that handle the reading and writing
    /// of keys to the disc
    /// </summary>
    public static class KeyHandler
    {
        /// <summary>
        /// Loads the public key local to the current machine. (named public.key)
        /// 
        /// Returns null if no local public key exists.
        /// </summary>
        /// <returns>A PublicKey object</returns>
        public static PublicKey? loadPublicKey()
        {
            if (!File.Exists(PublicKey.default_filename))
                return null;

            StreamReader sr = new StreamReader(PublicKey.default_filename);
            string JSON = sr.ReadToEnd();

            var jsonDoc = JsonDocument.Parse(JSON);
            var root = jsonDoc.RootElement;

            string? key = root.GetProperty("key").GetString();
            byte[] keyBytes = System.Convert.FromBase64String(key);

            int eBytes = BitConverter.ToInt32(keyBytes, 0);
            byte[] byteLargeE = new byte[eBytes];
            for (int i = 4; i < 4 + eBytes; i++)
                byteLargeE[i - 4] = keyBytes[i];
            Array.Reverse(byteLargeE);//to correct for endianness
            BigInteger E = new BigInteger(byteLargeE);

            int nBytes = BitConverter.ToInt32(keyBytes, 4 + eBytes);
            byte[] byteLargeN = new byte[nBytes];
            for (int i = 4 + eBytes + 4; i < 4 + eBytes + 4 + nBytes; i++)
                byteLargeN[i - (4 + eBytes + 4)] = keyBytes[i];
            Array.Reverse(byteLargeN);//to correct for endianness
            BigInteger N = new BigInteger(byteLargeN);

            return new PublicKey(nBytes * 8, N, eBytes * 8, E, false);//translate bytes to bits for the key constructor
        }

        /// <summary>
        /// Loads the private key local to the current machine. (named private.key)
        /// 
        /// Returns null if no local private key exists.
        /// </summary>
        /// <returns>A private key object</returns>
        public static PrivateKey? loadPrivateKey()
        {
            return null;//implement
        }

        /// <summary>
        /// Loads the public keys on the current machine that are of other users.
        /// 
        /// Returns an empty array if no other public keys exist.
        /// </summary>
        /// <returns>An array of public key objects</returns>
        public static PublicKey[] loadUserKeys()
        {
            return null;
        }
    }

    /// <summary>
    /// Stores the common portion of a key pair using a BigInteger
    /// </summary>
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

            PublicKey publicKey = new PublicKey(keysize, N, 16, E, true);
            PrivateKey privateKey = new PrivateKey(keysize, N, Utils.computeMinBits(D), D);
            return new Tuple<PublicKey, PrivateKey>(publicKey, privateKey);
        }
    }

    /// <summary>
    /// Stores the public portion of a key pair using a BigInteger
    /// </summary>
    public class PublicKey : Key
    {
        public const string default_filename = "public.key";

        /// <summary>
        /// The email associated with this public key. If null then
        /// this key is local to this machine and uses the default_filename.
        /// </summary>
        private string? email;

        /// <summary>
        /// The size in bits of the public key
        /// </summary>
        private int e;

        /// <summary>
        /// The public key
        /// </summary>
        private BigInteger E;

        /// <summary>
        /// Creates a public key. If writeToFile is true than the key is
        /// written to the disk with 'default_filename'. If a file with that name already exists
        /// than it is overwritten.
        /// </summary>
        /// <param name="n">The size in bits of the key</param>
        /// <param name="N">The key</param>
        /// <param name="e">The size in bits of the public key</param>
        /// <param name="E">The public key</param>
        /// <param name="writeToFile">The flag for writing</param>
        public PublicKey(int n, BigInteger N, int e, BigInteger E, bool writeToFile) : base(n, N)
        {
            this.e = e;
            this.E = E;
            this.email = null;
            if (writeToFile)
            {
                var base64encodedkey = encodeKeyIn64();
                var json = $"{{\"email\":\"\", \"key\":\"{base64encodedkey}\"}}";
                FileInfo f = new FileInfo(default_filename);
                using (StreamWriter sw = f.CreateText())
                {
                    sw.Write(json);
                }
            }
        }

        /// <summary>
        /// Creates a public key in relation to a given email. If writeToFile is true
        /// than the key is written to the disc with the email as its property and
        /// filename.
        /// </summary>
        /// <param name="n">The size in bits of the key</param>
        /// <param name="N">The key</param>
        /// <param name="e">The size in bits of the public key</param>
        /// <param name="E">The public key</param>
        /// <param name="email">The email to labe the key with</param>
        /// <param name="writeToFile">The flag for writing</param>
        public PublicKey(int n, BigInteger N, int e, BigInteger E, string email, bool writeToFile) : base(n, N)
        {
            this.e = e;
            this.E = E;
            this.email = email;
            if (writeToFile)
            {
                var base64encodedkey = encodeKeyIn64();
                var json = $"{{\"email\":\"{this.email}\", \"key\":\"{base64encodedkey}\"}}";
                FileInfo f = new FileInfo($"{email}.key");
                using (StreamWriter sw = f.CreateText())
                {
                    sw.Write(json);
                }
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
        public string encodeKeyIn64()
        {
            List<byte> byteSequence = new List<byte>();
            // the small e value
            byte[] eBytes = BitConverter.GetBytes((int)Math.Ceiling(e / 8.0));
            for (int i = 0; i < 4; i++)
                byteSequence.Add(eBytes[i]);
            // the big E value
            byte[] bigEBytes = E.ToByteArray();
            Array.Reverse(bigEBytes);
            if (bigEBytes[0] == 0)
            {
                for (int i = 1; i < bigEBytes.Length; i++)
                    byteSequence.Add(bigEBytes[i]);
            }
            else
            {
                foreach (var b in bigEBytes)
                    byteSequence.Add(b);
            }
            // the small n value
            byte[] nBytes = BitConverter.GetBytes((int)Math.Ceiling(getKeysize() / 8.0));
            foreach (var b in nBytes)
                byteSequence.Add(b);
            // the big N value
            byte[] bigNBytes = getN().ToByteArray();
            Array.Reverse(bigNBytes);
            if (bigNBytes[0] == 0)
            {
                for (int i = 1; i < bigNBytes.Length; i++)
                    byteSequence.Add(bigNBytes[i]);
            }
            else
            {
                foreach (var b in bigNBytes)
                    byteSequence.Add(b);
            }

            return System.Convert.ToBase64String(byteSequence.ToArray());
        }

        /// <summary>
        /// Decodes a key from base64 into a public key object
        /// </summary>
        /// <returns>The object that represents this public key</returns>
        public PublicKey decodeKeyFrom64(string encodedKey)
        {
            return null;
        }
    }

    /// <summary>
    /// Stores the private portion of a key pair using a BigInteger
    /// </summary>
    public class PrivateKey : Key
    {
        const string filename = "private.key";

        /// <summary>
        /// The list of emails associated with this local private key
        /// </summary>
        private List<string> emails;

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
            this.emails = new List<string>();
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
        public string encodeKeyIn64()
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

        /// <summary>
        /// Decodes a key from base 64 into a private key object
        /// </summary>
        /// <returns>The private key object</returns>
        public static PrivateKey decodeKeyFrom64(string encodedKey)
        {
            return null;
        }
    }
}