using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Identity.Client;

namespace CertAuthPoc;
internal class AuthService
{
    public async Task<string> GetAccessToken(
        string keyVaultUrl, 
        string certName, 
        string clientId,
        string authority,
        string tenantId)
    {
        var defaultAzureCredentialOptions = new DefaultAzureCredentialOptions()
        {
            AuthorityHost = AzureAuthorityHosts.AzureGovernment,
        };

        var defaultAzureCredential = new DefaultAzureCredential(defaultAzureCredentialOptions);
        //var certificateClient = new CertificateClient(vaultUri: new Uri(keyVaultUrl), defaultAzureCredential);
        //var certificate = await certificateClient.GetCertificateAsync(certName);
        var secretClient = new SecretClient(vaultUri: new Uri(keyVaultUrl), defaultAzureCredential);
        var secret = await secretClient.GetSecretAsync(certName);
        var bytes = Convert.FromBase64String(secret.Value.Value);
        var x509Cert = new X509Certificate2(bytes, string.Empty, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        var confidentialClientApplicationBuilder = ConfidentialClientApplicationBuilder
            .Create(clientId)
            .WithAuthority(authority, tenantId)
            .WithCertificate(x509Cert)
            .Build();

        var scopes = new string[] { $"api://{clientId}/.default" };
        var acquireTokenForClientParameterBuilder = confidentialClientApplicationBuilder.AcquireTokenForClient(scopes);
        var authenticationResult = await acquireTokenForClientParameterBuilder.ExecuteAsync().ConfigureAwait(false);
        return authenticationResult.AccessToken;
    }
}
