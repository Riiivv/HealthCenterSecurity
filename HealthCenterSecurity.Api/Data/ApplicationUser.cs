using Microsoft.AspNetCore.Identity;

namespace HealthCenterSecurity.Data;

public class ApplicationUser : IdentityUser
{
    public string CprNumber { get; set; } = string.Empty;
}