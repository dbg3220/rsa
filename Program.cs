using rsa.PrimeGen;
using rsa.Keys;
using rsa.RequestHandler;
using System.Text.Json;

namespace rsa
{
    /// <summary>
    /// Main class for this RSA Program
    /// </summary>
    class Program
    {
        private const string keyGen = "keyGen";
        private const string sendKey = "sendKey";
        private const string getKey = "getKey";
        private const string sendMsg = "sendMsg";
        private const string getMsg = "getMsg";

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("No command line option provided");
                Environment.Exit(1);
            }
            switch (args[0])
            {
                case keyGen:
                    KeyGen(args);
                    break;
                case sendKey:
                    SendKey(args);
                    break;
                case getKey:
                    GetKey(args);
                    break;
                case sendMsg:
                    SendMsg(args);
                    break;
                case getMsg:
                    GetMsg(args);
                    break;
                default:
                    Console.WriteLine($"'{args[0]}' option not recognized");
                    Environment.Exit(1);
                    break;
            }
        }

        /// <summary>
        /// Handler method for the keyGen command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void KeyGen(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Integer keysize must be provided");
                Environment.Exit(1);
            }
            int keysize = 0;
            try
            {
                keysize = Int32.Parse(args[1]);
            }
            catch (Exception)
            {
                Console.WriteLine("A valid integer must be provided");
                Environment.Exit(1);
            }
            Key.generateKeyPair(keysize);
        }

        /// <summary>
        /// Handler method for the sendKey command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void SendKey(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("email must be provided");
                Environment.Exit(1);
            }
            PublicKey publicKey = KeyHandler.loadPublicKey();
            if (publicKey == null)
            {
                Console.WriteLine("No Key Exists");
                Environment.Exit(1);
            }
            Controller c = new Controller();
            HttpResponseMessage response = c.keyPUT(args[1], publicKey.encodeKeyIn64());
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Key saved");
                PrivateKey privateKey = KeyHandler.loadPrivateKey();
                privateKey.addToEmailList(args[1]);
                privateKey.writeToDisc();
            }
            else
                Console.WriteLine("Could not access the server");
        }

        /// <summary>
        /// Handler method for the getKey command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void GetKey(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("email must be provided");
                Environment.Exit(1);
            }
            Controller c = new Controller();
            HttpResponseMessage response = c.keyGET(args[1]);
            if (response.IsSuccessStatusCode)
            {
                Task<string> task = response.Content.ReadAsStringAsync();
                task.Wait();
                var data = task.Result;
                var jsonDoc = JsonDocument.Parse(data);
                var root = jsonDoc.RootElement;

                string email = root.GetProperty("email").GetString();
                string encoded_key = root.GetProperty("key").GetString();

                PublicKey key = KeyHandler.loadKeyImmediate(email, encoded_key);
                key.writeToDisc();
            }
            else
            {
                Console.WriteLine("Could not access the server");
            }
        }

        /// <summary>
        /// Handler method for the sendMsg command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void SendMsg(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("email and message must be provided");
                Environment.Exit(1);
            }

            PublicKey? userKey = KeyHandler.loadUserKey(args[1]);
            if (userKey == null)
            {
                Console.WriteLine($"Key does not exist for {args[1]}");
                Environment.Exit(1);
            }
            string encrypted_data = userKey.encrypt(args[2]);
            Controller c = new Controller();
            HttpResponseMessage response = c.messagePUT(args[1], encrypted_data);
            if (response.IsSuccessStatusCode)
                Console.WriteLine("Message written");
            else
                Console.WriteLine("Could not access the server");
        }

        /// <summary>
        /// Handler method for the getMsg command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void GetMsg(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("email must be provided");
                Environment.Exit(1);
            }

            PrivateKey myKey = KeyHandler.loadPrivateKey();
            if (!myKey.getEmailList().Contains(args[1]))
            {
                Console.WriteLine("");
            }
            Controller c = new Controller();
            HttpResponseMessage response = c.messageGET(args[1]);
            if (response.IsSuccessStatusCode)
            {
                Task<string> task = response.Content.ReadAsStringAsync();
                task.Wait();
                var data = task.Result;
                var jsonDoc = JsonDocument.Parse(data);
                var root = jsonDoc.RootElement;

                string encrypted_data = root.GetProperty("content").GetString();

                string decrypted_data = myKey.decrypt(encrypted_data);
                Console.WriteLine(decrypted_data);
            }
            else
                Console.WriteLine("Could not access the server");
        }
    }
}