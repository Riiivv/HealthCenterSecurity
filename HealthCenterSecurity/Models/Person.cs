using System.ComponentModel.DataAnnotations;

namespace HealthCenterSecurity.Models;

public class Person
{
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string CprNumber { get; set; } = string.Empty;
}