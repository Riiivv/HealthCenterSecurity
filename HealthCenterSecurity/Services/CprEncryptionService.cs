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

        _key = Encoding.UTF8.GetBytes(keyText);
    }

    public string Hash(string cprNumber)
    {
        using var hmac = new HMACSHA256(_key);

        var bytes = Encoding.UTF8.GetBytes(cprNumber);
        var hash = hmac.ComputeHash(bytes);

        return Convert.ToBase64String(hash);
    }

    public bool Verify(string cprNumber, string storedHash)
    {
        var newHash = Hash(cprNumber);

        return CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(newHash),
            Convert.FromBase64String(storedHash));
    }
}