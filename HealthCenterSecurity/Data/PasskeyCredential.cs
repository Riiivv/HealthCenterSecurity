using System.ComponentModel.DataAnnotations;

namespace HealthCenterSecurity.Data;

public class PasskeyCredential
{
    public int Id { get; set; }

    [Required]
    public string UserId { get; set; } = string.Empty;

    public ApplicationUser User { get; set; } = null!;

    [Required]
    public byte[] CredentialId { get; set; } = [];

    [Required]
    public byte[] PublicKey { get; set; } = [];

    public uint SignatureCounter { get; set; }

    [Required]
    public string CredType { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}