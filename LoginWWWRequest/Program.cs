using Leaf.xNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using LoginWWWRequest.CryptoBranch;

namespace LoginWWWRequest
{
    internal class Program
    {
        public const string DefaultUg = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
        static void Main(string[] args)
        {
            TestLogin("100092897195918", "ymaulyae086"); // OK
        }
        private static void TestLogin(string user, string password)
        {
            HttpRequest httpRequest = CreateDefaultLeafClient();
            HttpResponse httpResponse = null;
            string ResponseStr = string.Empty;
            EnsureGetWWWLoginPageHDFull(httpRequest);
            httpResponse = httpRequest.Get("https://www.facebook.com/");
            if (httpResponse.StatusCode != Leaf.xNet.HttpStatusCode.OK)
            {
                // error while request to fb
                // handle this error here
                // return;
            }
            ResponseStr = httpResponse.ToString();
            string publicKey = Regex.Match(ResponseStr, "\"publicKey\":\"(.*?)\"").Groups[1].Value;
            string keyId = Regex.Match(ResponseStr, "\"keyId\":(.*?)}").Groups[1].Value;
            var action = Regex.Match(ResponseStr, "action=\"(.*?)\"").Groups[1].Value.Replace("amp;", "");
            var datr = Regex.Match(ResponseStr, "\"_js_datr\",\"(.*?)\"").Groups[1].Value;
            string lsd = Regex.Match(ResponseStr, "LSD\"(.*?){\"token\":\"(.*?)\"").Groups[2].Value;
            string jazoest = Regex.Match(ResponseStr, "name=\"jazoest\" value=\"(\\d+)\"").Groups[1].Value;
            string originUri = $"https://www.facebook.com{action}";
            string passwordEnc = FbEncPasswordHelper.GenerateEncPassword(password, publicKey, keyId, "5");
            httpRequest.Cookies.Add(new Cookie
            {
                Name = "datr",
                Value = datr,
                Path = "/",
                Domain = "facebook.com",
                Expired = false,
                Secure = true,
                Expires = DateTime.Now.AddDays(10)
            }); // add cookie datr to header
            Console.WriteLine("Password Encrypted : " + passwordEnc);
            Console.WriteLine();
            EnsurePostWWWLoginHDFull(httpRequest);
            var body = $"jazoest={jazoest}&lsd={lsd}&email={user}&login_source=comet_headerless_login&next=&encpass={WebUtility.UrlEncode(passwordEnc)}";
            httpResponse = httpRequest.Post("https://www.facebook.com/login/?privacy_mutation_token=", body, "application/x-www-form-urlencoded");
            ResponseStr = httpResponse.ToString();
            Console.WriteLine("Response Url :" + httpResponse.Address.ToString());
            Console.ReadLine();
        }
        private static void EnsureGetWWWLoginPageHDFull(HttpRequest httpRequest)
        {
            httpRequest["Accept-Language"] = "en-US,en;q=0.9";
            httpRequest["Sec-Fetch-Mode"] = "navigate";
            httpRequest["User-Agent"] = DefaultUg;
        }
        private static void EnsurePostWWWLoginHDFull(HttpRequest httpRequest)
        {
            httpRequest["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
            httpRequest["sec-fetch-dest"] = "document";
            httpRequest["sec-fetch-mode"] = "navigate";
            httpRequest["sec-fetch-site"] = "same-origin";
            httpRequest["sec-fetch-user"] = "?1";
            httpRequest["sec-ch-ua-mobile"] = "?0";
            httpRequest["sec-ch-ua-platform"] = "1";
            httpRequest["upgrade-insecure-requests"] = "\"Windows\"";
            httpRequest["cache-control"] = "max-age=0";
            httpRequest["upgrade-insecure-requests"] = "1";
            httpRequest["Accept-Language"] = "en-GB,en;q=0.9,en-US;q=0.8";
            httpRequest["User-Agent"] = DefaultUg;
        }
        private static HttpRequest CreateDefaultLeafClient()
        {
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.KeepAlive = true;
            httpRequest.IgnoreProtocolErrors = true;
            httpRequest.AllowAutoRedirect = true;
            httpRequest.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            httpRequest.Cookies = new CookieStorage(false);
            return httpRequest;
        }
    }
}
