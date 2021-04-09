using System.Threading.Tasks;

namespace Connor.Encryption
{
    public interface IEncryptionService
    {
        Task<byte[]> EncryptString(string toEncrypt, string password = null);
        Task<string> EncryptStringToBase64(string toEncrypt, string password = null);
        Task<string> DecryptToString(byte[] encryptedData, string password = null);
        Task<string> DecryptToStringFromBase64(string base64Data, string password = null);
    }
}
