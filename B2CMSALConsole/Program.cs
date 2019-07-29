using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Linq;


// https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-Applications

namespace MSALConsole
{
    class Program
    {
        // Configuration data:
        // Azure AD B2C Coordinates
        public static string Domain = "mrochonb2cprod";
        public static string Tenant = $"{Domain}.onmicrosoft.com";
        public static string ClientId = "4b457bbe-3a13-40a3-9db4-8ae430395680";
        public static string PolicySignUpSignIn = "B2C_1_BasicSUSI";
        public static string PolicyEditProfile = "b2c_1_edit_profile";
        public static string PolicyResetPassword = "B2C_1_PwdReset";

        public static string AuthorityBase = $"https://{Domain}.b2clogin.com/tfp/{Tenant}/";
        public static string Authority = $"{AuthorityBase}{PolicySignUpSignIn}";
        public static string AuthorityEditProfile = $"{AuthorityBase}{PolicyEditProfile}";
        public static string AuthorityPasswordReset = $"{AuthorityBase}{PolicyResetPassword}";
        public static string[] Scopes = new string[] { "https://mrochonb2cprod.onmicrosoft.com/webapi/read_policies" };


        // Registered app in AAD
        //static string _authority = "https://login.microsoftonline.com/tfp/mrochonb2cprod.onmicrosoft.com/B2C_1_BasicSUSI/oauth2/v2.0/authorize";
        //static string _authorityFormat = "https://{0}.b2clogin.com/tfp/{0}.onmicrosoft.com/{1}/oauth2/v2.0/authorize";
        //static string _publicClientId = "4b457bbe-3a13-40a3-9db4-8ae430395680";
        //static string[] _publicClientScopes = new string[] { "https://mrochonb2cprod.onmicrosoft.com/webapi/read_policies" };
        ////static string _publicClientRedirectUri = "urn:ietf:wg:oauth:2.0:oob";
        //static string _tenantShortName = "mrochonb2cprod";
        //static string _susiPolicy = "B2C_1_BasicSUSI";
        //static string _pwdResetPolicy = "B2C_1_PwdReset";

        static void Main(string[] args)
        {
            var p = new Program();

            p.UseAuthCodeGrantAsync().Wait();
            //p.UseResourceOwnerAsync().Wait();

            Console.ReadLine();
        }

        private async Task UseAuthCodeGrantAsync()
        {
            Console.WriteLine("Auth Code Grant - public client");
            AuthenticationResult tokens = null;
            try
            {
                var app = PublicClientApplicationBuilder
                    .Create(ClientId)
                        .WithB2CAuthority(Authority)
                            .Build();
                //var accts = await app.GetAccountsAsync();
                tokens = await app.AcquireTokenAsync(Scopes);
            } catch(Exception ex)
            {
                if (ex.Message.StartsWith("AADB2C90118")) // user clicked 'Forgot pwd'
                {
                    var app = PublicClientApplicationBuilder
                        .Create(ClientId)
                            .WithB2CAuthority(AuthorityPasswordReset)
                                .Build();
                    tokens = await app.AcquireTokenAsync(Scopes);
                }
                else
                {
                    Console.WriteLine(ex.Message);
                    return;
                }
            }
            ShowTokens(tokens);
        }
        private async Task UseResourceOwnerAsync()
        {
            Console.WriteLine("Resource Owner - public client");
            try
            {
                Authority = "https://login.microsoftonline.com/tfp/mrochonb2cprod.onmicrosoft.com/B2C_1_ROP/.well-known/openid-configuration";
                //Authority = "https://mrochonb2cprod.b2clogin.com/mrochonb2cprod.onmicrosoft.com/B2C_1_ROP/v2.0/";
                var pwd = new SecureString();
                foreach (var c in "Pass@word#1") pwd.AppendChar(c);
                var app = PublicClientApplicationBuilder
                    .Create(ClientId)
                        .WithB2CAuthority(Authority)
                            .Build();
                var accts = await app.GetAccountsAsync();
                var ar = await app.AcquireTokenByUsernamePasswordAsync(Scopes, "user1", pwd);
                ShowTokens(ar);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Console.ReadLine();
        }
        private static void ShowTokens(AuthenticationResult result)
        {
            try
            {
                foreach (var p in result.GetType().GetProperties())
                {
                    Console.WriteLine($"{p.Name}: {p.GetValue(result)}");
                }
            } catch(Exception)
            {

            }
            Console.WriteLine();
        }

    }
}
