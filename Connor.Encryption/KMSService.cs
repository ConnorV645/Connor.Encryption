using System;
using System.IO;
using System.Threading.Tasks;
using Amazon;
using Amazon.KeyManagementService;
using Microsoft.Extensions.Logging;

namespace Connor.Encryption
{
    public class KMSService : IEncryptionService
    {
        private readonly ILogger<KMSService> logger;
        private readonly AmazonKeyManagementServiceClient awsClient;
        private readonly string defaultKeyId;
        public KMSService(ILogger<KMSService> logger)
        {
            this.logger = logger;
            try
            {
                var sesAccess = Environment.GetEnvironmentVariable("KMSAccess");
                var sesSecret = Environment.GetEnvironmentVariable("KMSSecret");
                var sesRegion = Environment.GetEnvironmentVariable("KMSRegion");
                defaultKeyId = Environment.GetEnvironmentVariable("KMSDefaultKey");

                if (string.IsNullOrEmpty(sesAccess))
                {
                    throw new Exception("KMSAccess Environment Variable is not set");
                }
                if (string.IsNullOrEmpty(sesSecret))
                {
                    throw new Exception("KMSSecret Environment Variable is not set");
                }
                if (string.IsNullOrEmpty(sesRegion))
                {
                    throw new Exception("KMSRegion Environment Variable is not set");
                }

                var region = RegionEndpoint.GetBySystemName(sesRegion);
                if (region == null)
                {
                    throw new Exception("Invalid AWS Region");
                }

                awsClient = new AmazonKeyManagementServiceClient(sesAccess, sesSecret, region);
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
                logger?.LogError(ex, "Error Decrypting String");
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
                logger?.LogError(ex, "Error Encrypting String");
                throw;
            }
        }

        public async Task<string> EncryptStringToBase64(string toEncrypt, string password = null)
        {
            return Convert.ToBase64String(await EncryptString(toEncrypt, password));
        }
    }
}
