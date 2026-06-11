using HealthCenterSecurity.Data;
using HealthCenterSecurity.Models;
using HealthCenterSecurity.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HealthCenterSecurity.Pages.Persons;

public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _context;
    private readonly CprEncryptionService _encryptionService;

    public IndexModel(
        ApplicationDbContext context,
        CprEncryptionService encryptionService)
    {
        _context = context;
        _encryptionService = encryptionService;
    }

    [BindProperty]
    public Person Person { get; set; } = new();

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Person.CprNumber = _encryptionService.Hash(Person.CprNumber);

        _context.Persons.Add(Person);
        await _context.SaveChangesAsync();

        return RedirectToPage();
    }
}