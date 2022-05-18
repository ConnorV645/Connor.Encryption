using Amazon;
using Amazon.Extensions.NETCore.Setup;
using Amazon.KeyManagementService;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Connor.Encryption
{
    public class KMSService : IEncryptionService
    {
        private readonly ILogger<KMSService> logger;
        private readonly AmazonKeyManagementServiceClient awsClient;
        private readonly string defaultKeyId;
        public KMSService(ILogger<KMSService> logger, AWSOptions options = null)
        {
            this.logger = logger;
            try
            {
                var kmsAccess = Environment.GetEnvironmentVariable("KMSAccess");
                var kmsSecret = Environment.GetEnvironmentVariable("KMSSecret");
                var kmsRegion = Environment.GetEnvironmentVariable("KMSRegion");
                defaultKeyId = Environment.GetEnvironmentVariable("KMSDefaultKey");

                if (options != null && options.Credentials != null)
                {
                    awsClient = new(options.Credentials, options.Region);
                }
                else if (!string.IsNullOrEmpty(kmsAccess) && !string.IsNullOrEmpty(kmsSecret) && !string.IsNullOrEmpty(kmsRegion))
                {
                    var region = RegionEndpoint.GetBySystemName(kmsRegion);
                    if (region == null)
                    {
                        throw new Exception("Invalid AWS Region");
                    }

                    awsClient = new(kmsAccess, kmsSecret, region);
                }
                else
                {
                    var creds = Amazon.Runtime.FallbackCredentialsFactory.GetCredentials();
                    awsClient = new(creds);
                }
            }
            catch (Exception ex)
            {
                logger?.LogCritical(ex, "Error Starting KMSService");
            }
        }

        public async Task<string> DecryptToString(byte[] encryptedData, string password = null)
        {
            try
            {
                using var stream = new MemoryStream(encryptedData);
                var response = await awsClient.DecryptAsync(new()
                {
                    CiphertextBlob = stream
                });
                using var responseStream = response.Plaintext;
                using var reader = new StreamReader(responseStream);
                return await reader.ReadToEndAsync();
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Error KMS Decrypting String");
                throw;
            }
        }

        public async Task<string> DecryptToStringFromBase64(string base64Data, string password = null)
        {
            return await DecryptToString(Convert.FromBase64String(base64Data), password);
        }

        public async Task<byte[]> EncryptString(string toEncrypt, string password = null)
        {
            try
            {
                var keyId = password ?? defaultKeyId;
                if (string.IsNullOrWhiteSpace(keyId))
                {
                    throw new ArgumentException("KeyId Password Is Required");
                }

                using var stream = new MemoryStream();
                using var writer = new StreamWriter(stream);
                await writer.WriteAsync(toEncrypt);
                await writer.FlushAsync();

                var response = await awsClient.EncryptAsync(new()
                {
                    Plaintext = stream,
                    KeyId = keyId
                });

                return response.CiphertextBlob.ToArray();
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Error KMS Encrypting String");
                throw;
            }
        }

        public async Task<string> EncryptStringToBase64(string toEncrypt, string password = null)
        {
            return Convert.ToBase64String(await EncryptString(toEncrypt, password));
        }
    }
}
