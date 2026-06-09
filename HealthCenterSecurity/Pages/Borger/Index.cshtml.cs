using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HealthCenterSecurity.Pages.Borger;

[Authorize(Roles = "Borger")]
public class IndexModel : PageModel
{
    public void OnGet()
    {
    }
}