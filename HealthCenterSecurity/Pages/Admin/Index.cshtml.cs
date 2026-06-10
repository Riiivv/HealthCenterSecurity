using HealthCenterSecurity.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HealthCenterSecurity.Pages.Admin;

[Authorize(Roles = "Admin")]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IHttpClientFactory _httpClientFactory;

    public List<ApplicationUser> Users { get; set; } = new();
    public string? Message { get; set; }

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        IHttpClientFactory httpClientFactory)
    {
        _userManager = userManager;
        _httpClientFactory = httpClientFactory;
    }

    public void OnGet()
    {
        Users = _userManager.Users.ToList();
    }

    public async Task<IActionResult> OnPostDeleteAsync(string id)
    {
        var client = _httpClientFactory.CreateClient();

        if (Request.Headers.TryGetValue("Cookie", out var cookie))
        {
            client.DefaultRequestHeaders.Add("Cookie", cookie.ToString());
        }

        var response = await client.DeleteAsync($"https://localhost:7150/api/users/{id}");

        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            Message = $"API fejl: {(int)response.StatusCode} - {error}";
            Users = _userManager.Users.ToList();
            return Page();
        }

        Message = "Bruger slettet via API.";
        Users = _userManager.Users.ToList();
        return Page();
    }
}