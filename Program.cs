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
                WriteToError("No command line option provided");
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
                    WriteToError($"'{args[0]}' option not recognized");
                    Environment.Exit(1);
                    break;
            }
        }

        /// <summary>
        /// Takes a string and writes it to standard error. Followed
        /// by a new line character.
        /// </summary>
        /// <param name="msg">The string to write</param>
        static void WriteToError(string msg)
        {
            TextWriter errWriter = Console.Error;
            errWriter.WriteLine(msg);
        }

        /// <summary>
        /// Handler method for the keyGen command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void KeyGen(string[] args)
        {
            if (args.Length != 2)
            {
                WriteToError("Integer keysize must be provided");
                Environment.Exit(1);
            }
            int keysize = 0;
            try
            {
                keysize = Int32.Parse(args[1]);
            }
            catch (Exception)
            {
                WriteToError("A valid integer must be provided");
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
                WriteToError("email must be provided");
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
                PrivateKey privateKey = KeyHandler.loadPrivateKey();//write a method to modify the private key's list of email addresses
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
                WriteToError("email must be provided");
                Environment.Exit(1);
            }
            Controller c2 = new Controller();
            HttpResponseMessage response2 = c2.keyGET(args[1]);
            if (response2.IsSuccessStatusCode)
            {
                Task<string> task = response2.Content.ReadAsStringAsync();
                task.Wait();
                var data = task.Result;
                var jsonDoc = JsonDocument.Parse(data);
                var root = jsonDoc.RootElement;

                string email = root.GetProperty("email").GetString();
                string key = root.GetProperty("key").GetString();
            }
            // var jsonDoc = JsonDocument.Parse(JSON);
            // var root = jsonDoc.RootElement;

            // string? key = root.GetProperty("key").GetString();
            else
                Console.WriteLine("Could not access the server");
        }

        /// <summary>
        /// Handler method for the sendMsg command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void SendMsg(string[] args)
        {
            if (args.Length != 2)
            {
                WriteToError("email and message must be provided");
                Environment.Exit(1);
            }
            //replace the following code
            Console.WriteLine(sendMsg);

            //TODO
        }

        /// <summary>
        /// Handler method for the getMsg command
        /// </summary>
        /// <param name="args">The given command line arguments</param>
        static void GetMsg(string[] args)
        {
            if (args.Length != 2)
            {
                WriteToError("email must be provided");
                Environment.Exit(1);
            }
            //replace the following code
            Console.WriteLine(getMsg);

            //TODO
        }
    }
}