using System.Security.Cryptography;
using System.Text;

namespace HealthCenterSecurity.Services;

public class CprEncryptionService
{
    private readonly byte[] _key;

    public CprEncryptionService(IConfiguration configuration)
    {
        var keyText = configuration["CprEncryptionKey"]
            ?? throw new InvalidOperationException("CprEncryptionKey mangler i appsettings.json");

        _key = SHA256.HashData(Encoding.UTF8.GetBytes(keyText));
    }

    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();

        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        return Convert.ToBase64String(aes.IV) + ":" + Convert.ToBase64String(encryptedBytes);
    }

    public string Decrypt(string encryptedText)
    {
        var parts = encryptedText.Split(':');

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = Convert.FromBase64String(parts[0]);

        using var decryptor = aes.CreateDecryptor();

        var encryptedBytes = Convert.FromBase64String(parts[1]);
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }
}