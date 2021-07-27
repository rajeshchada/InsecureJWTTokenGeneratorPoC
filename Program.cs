using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace AADTokenGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            DateTime now = DateTime.UtcNow;
            long issuedAt = EpochTime.GetIntDate(now);
            long expirationTime = EpochTime.GetIntDate(now.AddHours(90));
            string[] amr = new[] { "rsa" };
            string deviceId = Guid.NewGuid().ToString();
            string oid = Guid.NewGuid().ToString();
            string tenantid = Guid.NewGuid().ToString();
            JwtPayload jwtPayload = new JwtPayload()
            {
                { "aud", Guid.NewGuid().ToString() },
                { "iss", $"https://sts.windows.net/{tenantid}/" },
                { "iat", issuedAt },
                { "nbf", issuedAt },
                { "exp", expirationTime },
                { "amr", amr },
                { "sub", deviceId },
                { "oid", oid },
                { "tid", tenantid },
                { "deviceid", deviceId },
                { "ver", "1.0" }
            };

            // RSA private key parameters
            RSACryptoServiceProvider dlsRsaProviderTest = new RSACryptoServiceProvider();
            RSAParameters dlsRsaParametersTest = new RSAParameters()
            {
                Modulus = Convert.FromBase64String("<Modulus>"),
                Exponent = Convert.FromBase64String("<Exponent>"),
                P = Convert.FromBase64String("<P>"),
                Q = Convert.FromBase64String("<Q>"),
                DP = Convert.FromBase64String("<DP>"),
                DQ = Convert.FromBase64String("<DQ>"),
                InverseQ = Convert.FromBase64String("<InverseQ>"),
                D = Convert.FromBase64String("<D>")
            };
            dlsRsaProviderTest.ImportParameters(dlsRsaParametersTest);
            SecurityKey rsaPrivateKey = new RsaSecurityKey(dlsRsaProviderTest);
            SigningCredentials jwtCredentials = new SigningCredentials(rsaPrivateKey, SecurityAlgorithms.RsaSha256);

            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
                new JwtHeader(jwtCredentials), jwtPayload);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            Console.WriteLine(handler.WriteToken(jwtSecurityToken));
            Console.Read();
        }
    }
}
