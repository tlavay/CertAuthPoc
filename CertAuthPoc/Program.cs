
using CertAuthPoc;

var authService = new AuthService();

var keyVaultUrl = "";
var certificateName = "tyler-sample-cert";
var clientId = "";
var authority = "https://login.microsoftonline.us/";
var tenantId = "63296244-ce2c-46d8-bc36-3e558792fbee";
authService.GetAccessToken(
    keyVaultUrl, 
    certificateName,
    clientId,
    authority,
    tenantId).Wait();
