using rsa.PrimeGen;
using rsa.Keys;
using rsa.RequestHandler;

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
                    break;
                case sendKey:
                    if (args.Length != 2)
                    {
                        WriteToError("email must be provided");
                        Environment.Exit(1);
                    }
                    PublicKey? publicKey = KeyHandler.loadPublicKey();
                    if (publicKey == null)
                    {
                        Console.WriteLine("No Key Exists");
                        Environment.Exit(1);
                    }
                    Controller c = new Controller();
                    HttpResponseMessage response = c.keyPUT(args[1], publicKey.encodeKeyIn64());
                    if (response.IsSuccessStatusCode)
                        Console.WriteLine("Key saved");
                    else
                        Console.WriteLine("Could not access the server");
                    break;
                case getKey:
                    if (args.Length != 2)
                    {
                        WriteToError("email must be provided");
                        Environment.Exit(1);
                    }
                    //replace the following code
                    Console.WriteLine(getKey);
                    break;
                case sendMsg:
                    if (args.Length != 2)
                    {
                        WriteToError("email and message must be provided");
                        Environment.Exit(1);
                    }
                    //replace the following code
                    Console.WriteLine(sendMsg);
                    break;
                case getMsg:
                    if (args.Length != 2)
                    {
                        WriteToError("email must be provided");
                        Environment.Exit(1);
                    }
                    //replace the following code
                    Console.WriteLine(getMsg);
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
    }
}