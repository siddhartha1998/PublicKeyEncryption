using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var input = new
{
    mobileNumber = "9843559404",
    accountNumber = "10000111222",
    amount = 100,
    bankCode = "LAXMI"
};

// Convert plain text payload to cypher text data using AES algorithm
var payload = JsonConvert.SerializeObject(input);
byte[] inputBytes = Encoding.UTF8.GetBytes(payload);

string clientEncryptionCertificatePath = Path.Combine(Directory.GetCurrentDirectory(), $@"Certificate\pkcs8clientEncryptionPrivateKey.key");
string clientSignatureCertificatePath = Path.Combine(Directory.GetCurrentDirectory(), $@"Certificate\pkcs8clientSignaturePrivateKey.key");
string clientSignaturePublicKeyCertificatePath = Path.Combine(Directory.GetCurrentDirectory(), $@"Certificate\clientSignaturePublicKey.pem");
string serverEncryptionCertificatePath = Path.Combine(Directory.GetCurrentDirectory(), $@"Certificate\serverEncryptionPublicKey.pem");
string serverEncryptionPrivatekeyCertificatePath = Path.Combine(Directory.GetCurrentDirectory(), $@"Certificate\pkcs8serverEncryptionPrivateKey.key");

var clientEcryptionPrivateKey = File.ReadAllLines(clientEncryptionCertificatePath)
                                    .Skip(1)
                                    .SkipLast(1)
                                    .Aggregate((a, b) => a + b);

var clientSignaturePrivateKey = File.ReadAllLines(clientSignatureCertificatePath)
                                     .Skip(1)
                                     .SkipLast(1)
                                     .Aggregate((a, b) => a + b);

var clientSignaturePublicKey = File.ReadAllLines(clientSignaturePublicKeyCertificatePath)
                                     .Skip(1)
                                     .SkipLast(1)
                                     .Aggregate((a, b) => a + b);

var serverEcryptionPublicKey = File.ReadAllLines(serverEncryptionCertificatePath)
                                     .Skip(1)
                                     .SkipLast(1)
                                     .Aggregate((a, b) => a + b);

var serverEcryptionPrivateKey = File.ReadAllLines(serverEncryptionPrivatekeyCertificatePath)
                                     .Skip(1)
                                     .SkipLast(1)
                                     .Aggregate((a, b) => a + b);

byte[] clientEncryptionPrivateKeyBytes = Convert.FromBase64String(clientEcryptionPrivateKey);
byte[] clientSignatureprivateKeyBytes = Convert.FromBase64String(clientSignaturePrivateKey);
byte[] clientSignaturepublicKeyBytes = Convert.FromBase64String(clientSignaturePublicKey);
byte[] serverEcryptionPublicKeyBytes = Convert.FromBase64String(serverEcryptionPublicKey);
byte[] serverEcryptionPrivateKeyBytes = Convert.FromBase64String(serverEcryptionPrivateKey);

var key = RSA.Create();
key.ImportPkcs8PrivateKey(clientEncryptionPrivateKeyBytes, out _);

SymmetricAlgorithm aes = Aes.Create();
aes.GenerateKey();

var secretKey = aes.Key;
var foo1 = System.Convert.ToBase64String(secretKey);
aes.KeySize = 256;

var cypherPayloadData = GenerateCypherPayload(inputBytes, aes);

var secret = GenerateCypherSecret(secretKey);

var signature = GetHashDataOfPayload(System.Convert.FromBase64String(cypherPayloadData));

DecryptData(cypherPayloadData, secret, signature);

string GenerateCypherPayload(byte[] inputBytes, SymmetricAlgorithm aes)
{
    var cypherPayloadData = aes.EncryptEcb(inputBytes,PaddingMode.PKCS7);
    var base64EncodedPayload = System.Convert.ToBase64String(cypherPayloadData);
    return base64EncodedPayload;
}

string GenerateCypherSecret(byte[] secretKey)
{
    // Convert Secret key into cypher text using RSA algorithm
   // RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
    var key = RSA.Create();
    key.KeySize = 2048;
    key.ImportSubjectPublicKeyInfo(serverEcryptionPublicKeyBytes, out _);
    var cypherSecretKey = key.Encrypt(secretKey, RSAEncryptionPadding.Pkcs1);
    var base64EncodedSecretKey = System.Convert.ToBase64String(cypherSecretKey);
    return base64EncodedSecretKey;
}

string GetHashDataOfPayload(byte[] PayloadData)
{
    // Get Hash Signature of Payload and secret key using SHA 256 algorithm
    SHA256 sha256 = SHA256.Create();
    var digestPayload = sha256.ComputeHash(PayloadData);

    var signByRSA = RSA.Create();
    signByRSA.ImportPkcs8PrivateKey(clientSignatureprivateKeyBytes, out _);
    byte[] signature = signByRSA.SignHash(digestPayload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var base64EncodedSignature = System.Convert.ToBase64String(signature);
    return base64EncodedSignature;
}


bool DecryptData(string cypherPayloadData, string secretKey, string signature)
{
    Console.WriteLine($"{cypherPayloadData} {Environment.NewLine} {secretKey} {Environment.NewLine} {signature}");
    //  RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
    var rsa = RSA.Create();
    rsa.ImportPkcs8PrivateKey(serverEcryptionPrivateKeyBytes, out _);
    byte[] byteSecret = System.Convert.FromBase64String(secretKey);
    var decryptsecret = rsa.Decrypt(byteSecret,RSAEncryptionPadding.Pkcs1);
    var foo = System.Convert.ToBase64String(decryptsecret);

    SymmetricAlgorithm aes = Aes.Create();
    aes.Key = decryptsecret;
    byte[] bytePayload = System.Convert.FromBase64String(cypherPayloadData);
    var decryptPayload = aes.DecryptEcb(bytePayload, PaddingMode.PKCS7);
    var data = System.Text.Encoding.UTF8.GetString(decryptPayload);
    Console.WriteLine(data);

    SHA256 sHA256 = SHA256.Create();
    var digestpayload = sHA256.ComputeHash(bytePayload);
    byte[] signatureByte = System.Convert.FromBase64String(signature);
    var signByrsa = RSA.Create();
    signByrsa.ImportSubjectPublicKeyInfo(clientSignaturepublicKeyBytes, out _);
    bool hasingSignature = signByrsa.VerifyHash(digestpayload, signatureByte, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    if (hasingSignature)
    {
        return true;
    }
    else
    {
        return false;
    }
}




