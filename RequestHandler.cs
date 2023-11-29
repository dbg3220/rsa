using System.Reflection.Metadata;
using System.Text;
using rsa.Keys;

namespace rsa.Controller
{
    /// <summary>
    /// Class to Handle all http operations
    /// </summary>
    public class Controller
    {
        private readonly HttpClient client;

        /// <summary>
        /// The url to the server used for this project
        /// </summary>
        private static readonly string serverURL = "http://kayrun.cs.rit.edu:5000";

        /// <summary>
        /// Public constructor for this Controller
        /// </summary>
        public Controller()
        {
            client = new HttpClient();
        }

        /// <summary>
        /// Performs a GET request to the given url
        /// </summary>
        /// <param name="url">The url to request</param>
        /// <returns>The total response from the server</returns>
        private HttpResponseMessage makeGETRequest(string url)
        {
            Task<HttpResponseMessage> task = client.GetAsync(url);
            task.Wait();
            return task.Result;
        }

        /// <summary>
        /// Performs a PUT request to teh given url with the given json body
        /// </summary>
        /// <param name="url">The url to request</param>
        /// <param name="JSON">The body to request with</param>
        /// <returns>The total response from the server</returns>
        private HttpResponseMessage makePUTRequest(string url, string JSON)
        {
            Task<HttpResponseMessage> task = client.PutAsync(url, createJSONBody(JSON));
            task.Wait();
            return task.Result;
        }

        /// <summary>
        /// Takes a serialized json object and returns a usable C# object for http requests
        /// </summary>
        /// <param name="json">The JSON to use</param>
        /// <returns>The object to use in the requests</returns>
        private StringContent createJSONBody(string JSON)
        {
            return new StringContent(JSON, Encoding.UTF8, "application/json");
        }

        /// <summary>
        /// Performs a get message request on the server with the given email
        /// </summary>
        /// <param name="email">The email to get the message of</param>
        /// <returns>The result of the http request</returns>
        public HttpResponseMessage messageGET(string email)
        {
            var requestURL = serverURL + "/Message/" + email;
            return makeGETRequest(requestURL);
        }

        /// <summary>
        /// Performs a put message request on the server with the given email and message content
        /// strings
        /// </summary>
        /// <param name="email">The email to send the message to</param>
        /// <param name="message">The message content to put on the server, encrypted
        /// before hand and encoded as a base64 string</param>
        /// <returns>The result of the http request</returns>
        public HttpResponseMessage messagePUT(string email, string message_content)
        {
            var requestURL = serverURL + "/Message/" + email;
            return null;
        }

        /// <summary>
        /// Performs a get key request on the server with the given email
        /// </summary>
        /// <param name="email">The email of the user to retrieve the key of</param>
        /// <returns>The result of the http request</returns>
        public HttpResponseMessage keyGET(string email)
        {
            return null;
        }

        /// <summary>
        /// Performs a put key request on the server with the given email and key strings
        /// </summary>
        /// <param name="email">The email of the user to put the key of</param>
        /// <param name="key">The key, encoded as a base64 string</param>
        /// <returns></returns>
        public HttpResponseMessage keyPUT(string email, string key)
        {
            return null;
        }
    }
}