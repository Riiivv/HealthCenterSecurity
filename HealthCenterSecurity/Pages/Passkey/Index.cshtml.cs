using System.ComponentModel.DataAnnotations;
using HealthCenterSecurity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HealthCenterSecurity.Pages.Passkey;

public class RegisterModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [BindProperty]
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    public string? Message { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Message = "REGISTER HANDLER RAMT";

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var existingUser = await _userManager.FindByEmailAsync(Email);

        if (existingUser != null)
        {
            Message = "Brugeren findes allerede.";
            return Page();
        }

        var user = new ApplicationUser
        {
            UserName = Email,
            Email = Email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user);

        if (!result.Succeeded)
        {
            Message = string.Join(", ", result.Errors.Select(e => e.Description));
            return Page();
        }

        await _userManager.AddToRoleAsync(user, "Borger");

        Message = "Passkey-demo bruger oprettet uden password.";
        return Page();
    }

    public async Task<IActionResult> OnPostLoginAsync()
    {
        Message = "LOGIN HANDLER RAMT";

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Email);

        if (user == null)
        {
            Message = "Brugeren findes ikke.";
            return Page();
        }

        if (user.PasswordHash != null)
        {
            Message = "Denne bruger er ikke passwordless.";
            return Page();
        }

        await _signInManager.SignInAsync(user, isPersistent: false);

        return RedirectToPage("/Borger/Index");
    }
}