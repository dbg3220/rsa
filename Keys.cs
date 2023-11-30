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

            string JSON = "";
            using (StreamReader sr = new StreamReader(PublicKey.default_filename))
            {
                JSON = sr.ReadToEnd();
            }

            var jsonDoc = JsonDocument.Parse(JSON);
            var root = jsonDoc.RootElement;

            string? encoded_key = root.GetProperty("key").GetString();
            byte[] keyBytes = Convert.FromBase64String(encoded_key);

            //Delete later
            foreach (var b in keyBytes)
                Console.Write(b + " ");

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

            return new PublicKey(N, E);
        }

        /// <summary>
        /// Loads the private key local to the current machine. (named private.key)
        /// 
        /// Returns null if no local private key exists.
        /// </summary>
        /// <returns>A private key object</returns>
        public static PrivateKey? loadPrivateKey()
        {
            if (!File.Exists(PrivateKey.filename))
                return null;

            string JSON = "";
            using (StreamReader sr = new StreamReader(PrivateKey.filename))
            {
                JSON = sr.ReadToEnd();
            }

            var jsonDoc = JsonDocument.Parse(JSON);
            var root = jsonDoc.RootElement;

            JsonElement emailArray = root.GetProperty("email");
            List<string> emails = emailArray.EnumerateArray().Select(element => element.GetString()).ToList();

            string? encoded_key = root.GetProperty("key").GetString();
            byte[] keyBytes = Convert.FromBase64String(encoded_key);

            int dBytes = BitConverter.ToInt32(keyBytes, 0);
            byte[] byteLargeD = new byte[dBytes];
            for (int i = 4; i < 4 + dBytes; i++)
                byteLargeD[i - 4] = keyBytes[i];
            Array.Reverse(byteLargeD);//to correct for endianness
            BigInteger D = new BigInteger(byteLargeD);

            int nBytes = BitConverter.ToInt32(keyBytes, 4 + dBytes);
            byte[] byteLargeN = new byte[nBytes];
            for (int i = 4 + dBytes + 4; i < 4 + dBytes + 4 + nBytes; i++)
                byteLargeN[i - (4 + dBytes + 4)] = keyBytes[i];
            Array.Reverse(byteLargeN);//to correct for endianness
            BigInteger N = new BigInteger(byteLargeN);

            return new PrivateKey(N, D, emails);
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

        /// <summary>
        /// Creates a public key object given the email and key as a base64
        /// encoded string.
        /// </summary>
        /// <param name="email">The email of the user whose key it is</param>
        /// <param name="encoded_key">The encoded key</param>
        /// <returns>The public key object</returns>
        public static PublicKey loadKeyImmediate(string email, string encoded_key)
        {
            byte[] keyBytes = Convert.FromBase64String(encoded_key);

            //Delete later
            foreach (var b in keyBytes)
                Console.Write(b + " ");

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

            return new PublicKey(N, E, email);
        }
    }

    /// <summary>
    /// Stores the common portion of a key pair using a BigInteger
    /// </summary>
    public class Key
    {
        /// <summary>
        /// The key
        /// </summary>
        private BigInteger N;

        /// <summary>
        /// Creates a key object with the common portion of a public/private key pair
        /// </summary>
        /// <param name="N">The key</param>
        public Key(BigInteger N)
        {
            this.N = N;
        }

        /// <summary>
        /// Getter for the key value
        /// </summary>
        /// <returns>The key value</returns>
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

            PublicKey publicKey = new PublicKey(N, E);
            publicKey.writeToDisc();
            PrivateKey privateKey = new PrivateKey(N, D);
            privateKey.writeToDisc();
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
        /// The public key
        /// </summary>
        private BigInteger E;

        /// <summary>
        /// Creates a public key object with no associated email.
        /// 
        /// Meant to represent a public key that is local to the current machine.
        /// (The field 'email' will be null).
        /// </summary>
        /// <param name="N">The key</param>
        /// <param name="E">The public key</param>
        public PublicKey(BigInteger N, BigInteger E) : base(N)
        {
            this.E = E;
            this.email = null;
        }

        /// <summary>
        /// Creates a public key in relation to a given email. If writeToFile is true
        /// than the key is written to the disc with the email as its property and
        /// filename.
        /// </summary>
        /// <param name="N">The key</param>
        /// <param name="E">The public key</param>
        /// <param name="email">The email to labe the key with</param>
        public PublicKey(BigInteger N, BigInteger E, string email) : base(N)
        {
            this.E = E;
            this.email = email;
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
            // the number of bytes of the E value(itself represented as a length 4 array of bytes, big endian)
            byte[] eBytes = BitConverter.GetBytes(Utils.computeMinBytes(E));
            for (int i = 0; i < 4; i++)
                byteSequence.Add(eBytes[i]);
            // the E value
            byte[] bigEBytes = E.ToByteArray();
            Array.Reverse(bigEBytes);
            if (bigEBytes[0] == 0)//trim off the sign bit
            {
                for (int i = 1; i < bigEBytes.Length; i++)
                    byteSequence.Add(bigEBytes[i]);
            }
            else
            {
                foreach (var b in bigEBytes)
                    byteSequence.Add(b);
            }
            // the number of bytes of the N value(itself represented as a length 4 array of bytes, big endian)
            byte[] nBytes = BitConverter.GetBytes(Utils.computeMinBytes(getN()));
            foreach (var b in nBytes)
                byteSequence.Add(b);
            // the N value
            byte[] bigNBytes = getN().ToByteArray();
            Array.Reverse(bigNBytes);
            if (bigNBytes[0] == 0)//trim off the sign bit
            {
                for (int i = 1; i < bigNBytes.Length; i++)
                    byteSequence.Add(bigNBytes[i]);
            }
            else
            {
                foreach (var b in bigNBytes)
                    byteSequence.Add(b);
            }

            return Convert.ToBase64String(byteSequence.ToArray());
        }

        /// <summary>
        /// Writes this private key object to the current machine
        /// 
        /// If the 'email' field is null than the default filename is used.
        /// Otherwise the key is written using the email in the pattern
        ///     'email'.key
        /// </summary>
        public void writeToDisc()
        {
            if (email == null)
            {
                var base64encodedkey = encodeKeyIn64();
                var json = $"{{\"email\":\"\", \"key\":\"{base64encodedkey}\"}}";
                FileInfo f = new FileInfo(default_filename);
                using (StreamWriter sw = f.CreateText())
                {
                    sw.Write(json);
                }
            }
            else
            {
                var base64encodedkey = encodeKeyIn64();
                var json = $"{{\"email\":\"{email}\", \"key\":\"{base64encodedkey}\"}}";
                FileInfo f = new FileInfo(email + ".key");
                using (StreamWriter sw = f.CreateText())
                {
                    sw.Write(json);
                }
            }
        }
    }

    /// <summary>
    /// Stores the private portion of a key pair using a BigInteger
    /// </summary>
    public class PrivateKey : Key
    {
        public const string filename = "private.key";

        /// <summary>
        /// The list of emails associated with this local private key
        /// </summary>
        private List<string> emails;

        /// <summary>
        /// The private key
        /// </summary>
        private BigInteger D;

        /// <summary>
        /// Creates a private key object with an empty list of emails.
        /// </summary>
        /// <param name="N">The key</param>
        /// <param name="D">The private key</param>
        public PrivateKey(BigInteger N, BigInteger D) : base(N)
        {
            this.D = D;
            this.emails = new List<string>();
        }

        /// <summary>
        /// Creates a private key object with the given list of emails.
        /// </summary>
        /// <param name="N">The key</param>
        /// <param name="D">The private key</param>
        /// <param name="emails"></param>
        public PrivateKey(BigInteger N, BigInteger D, List<string> emails) : base(N)
        {
            this.D = D;
            this.emails = emails;
        }

        /// <summary>
        /// Getter for the private portion of the key
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
            // the number of bytes of the E value(itself represented as a length 4 array of bytes, big endian)
            byte[] eBytes = BitConverter.GetBytes(Utils.computeMinBytes(D));
            foreach (var b in eBytes)
                byteSequence.Add(b);
            // the D value
            byte[] bigEBytes = D.ToByteArray();
            Array.Reverse(bigEBytes);
            if (bigEBytes[0] == 0)//trim off the sign bit
            {
                for (int i = 1; i < bigEBytes.Length; i++)
                    byteSequence.Add(bigEBytes[i]);
            }
            else
            {
                foreach (var b in bigEBytes)
                    byteSequence.Add(b);
            }
            // the number of bytes of the N value(itself represented as a length 4 array of bytes, big endian)
            byte[] nBytes = BitConverter.GetBytes(Utils.computeMinBytes(getN()));
            foreach (var b in nBytes)
                byteSequence.Add(b);
            // the N value
            byte[] bigNBytes = getN().ToByteArray();
            Array.Reverse(bigNBytes);
            if (bigNBytes[0] == 0)//trim off the sign bit
            {
                for (int i = 1; i < bigNBytes.Length; i++)
                    byteSequence.Add(bigNBytes[i]);
            }
            else
            {
                foreach (var b in bigNBytes)
                    byteSequence.Add(b);
            }

            return Convert.ToBase64String(byteSequence.ToArray());
        }

        /// <summary>
        /// Writes this private key object to the current machine
        /// </summary>
        public void writeToDisc()
        {
            var jsonEmails = "[]";
            if (emails.Count != 0)
            {
                jsonEmails = "[";
                for (int i = 0; i < emails.Count - 1; i++)
                {
                    jsonEmails += $"\"{emails[i]}\",";
                }
                jsonEmails += $"\"{emails[emails.Count - 1]}\"]";
            }
            var base64encodedkey = encodeKeyIn64();
            var json = $"{{\"email\":{jsonEmails}, \"key\":\"{base64encodedkey}\"}}";
            FileInfo f = new FileInfo(filename);
            using (StreamWriter sw = f.CreateText())
            {
                sw.Write(json);
            }
        }

        /// <summary>
        /// Adds an email to the list of emails
        /// 
        /// This function DOES NOT write the updated object to the disc. To update
        /// the object on the current machine you must call writeToDisc() after this function.
        /// </summary>
        /// <param name="email">The email to add</param>
        public void addToEmailList(string email)
        {
            emails.Add(email);
        }
    }
}