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
// https://docs.microsoft.com/en-us/azure/active-directory-b2c/tutorial-create-tenant

namespace MSALConsole
{
    
    class Program
    {
        // Configuration data:
        // Azure AD B2C Configuration Variables
        public static string Domain = "B2C tenant name"; //replace with your own tenant name
        public static string Tenant = $"{Domain}.onmicrosoft.com";
        public static string ClientId = "cliend id provided during registration";
        public static string PolicySignUpSignIn = "B2C_1_BasicSUSI";
        public static string PolicyEditProfile = "b2c_1_edit_profile";
        public static string PolicyResetPassword = "B2C_1_PwdReset";

        public static string AuthorityBase = $"https://{Domain}.b2clogin.com/tfp/{Tenant}/";
        public static string Authority = $"{AuthorityBase}{PolicySignUpSignIn}";
        public static string AuthorityEditProfile = $"{AuthorityBase}{PolicyEditProfile}";
        public static string AuthorityPasswordReset = $"{AuthorityBase}{PolicyResetPassword}";
        public static string[] Scopes = new string[] { "https://tenant.onmicrosoft.com/webapi/read_policies" };


        // Registered app in AAD
        //static string _authority = "https://login.microsoftonline.com/tfp/tenant.onmicrosoft.com/B2C_1_BasicSUSI/oauth2/v2.0/authorize";
        //static string _authorityFormat = "https://{0}.b2clogin.com/tfp/{0}.onmicrosoft.com/{1}/oauth2/v2.0/authorize";
        //static string _publicClientId = "clientid";
        //static string[] _publicClientScopes = new string[] { "https://tenant.onmicrosoft.com/webapi/read_policies" };
        ////static string _publicClientRedirectUri = "urn:ietf:wg:oauth:2.0:oob";
        //static string _tenantShortName = "tenant";
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

        ///Do not use Resource Owner in production scenarios, this is a flawed grant or flow.
        private async Task UseResourceOwnerAsync()
        {
            
            Console.WriteLine("Resource Owner - public client");
            try
            {
                Authority = $"https://login.microsoftonline.com/tfp/{Tenant}/B2C_1_ROP/.well-known/openid-configuration";
                //Authority = $"https://{Domain}.b2clogin.com/{Tenant}/B2C_1_ROP/v2.0/";
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
