using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HealthCenterSecurity.Data;
using HealthCenterSecurity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HealthCenterSecurity.Areas.Identity.Pages.Account;

public class SecureRegisterModel : PageModel
{
    private const string SessionKey = "SecureRegister.PendingUser";
    private const string Issuer = "HealthCenterSecurity";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IUserStore<ApplicationUser> _userStore;
    private readonly CprEncryptionService _cprService;

    public SecureRegisterModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IUserStore<ApplicationUser> userStore,
        CprEncryptionService cprService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _userStore = userStore;
        _cprService = cprService;
    }

    [BindProperty]
    public RegisterInput Input { get; set; } = new();

    [BindProperty]
    public VerifyInput Verify { get; set; } = new();

    public bool ShowQrCode { get; set; }

    public string? SharedKey { get; set; }

    public string? AuthenticatorUri { get; set; }

    public string? Message { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostStartAsync()
    {
        ModelState.Clear();

        if (string.IsNullOrWhiteSpace(Input.Email))
        {
            Message = "Email mangler.";
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.CprNumber) || Input.CprNumber.Length != 10 || !Input.CprNumber.All(char.IsDigit))
        {
            Message = "CPR skal være 10 cifre.";
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Input.Password))
        {
            Message = "Password mangler.";
            return Page();
        }

        if (Input.Password != Input.ConfirmPassword)
        {
            Message = "Password og bekræft password matcher ikke.";
            return Page();
        }

        var existingUser = await _userManager.FindByEmailAsync(Input.Email);

        if (existingUser != null)
        {
            Message = "Brugeren findes allerede.";
            return Page();
        }

        var authenticatorKey = GenerateBase32Secret();

        var pendingUser = new PendingRegisterUser
        {
            Email = Input.Email,
            Password = Input.Password,
            CprNumber = Input.CprNumber,
            AuthenticatorKey = authenticatorKey
        };

        HttpContext.Session.SetString(SessionKey, JsonSerializer.Serialize(pendingUser));

        ShowQrCode = true;
        SharedKey = FormatKey(authenticatorKey);
        AuthenticatorUri = GenerateAuthenticatorUri(Input.Email, authenticatorKey);

        Message = "Scan QR-koden og indtast koden. Brugeren bliver først oprettet efter korrekt 2FA-kode.";

        return Page();
    }

    public async Task<IActionResult> OnPostVerifyAsync()
    {
        var json = HttpContext.Session.GetString(SessionKey);

        if (string.IsNullOrWhiteSpace(json))
        {
            Message = "Session udløbet. Start registreringen igen.";
            return Page();
        }

        var pendingUser = JsonSerializer.Deserialize<PendingRegisterUser>(json);

        if (pendingUser == null)
        {
            Message = "Registreringsdata kunne ikke læses. Start igen.";
            return Page();
        }

        var code = Verify.Code.Replace(" ", "").Replace("-", "");

        if (!VerifyTotpCode(pendingUser.AuthenticatorKey, code))
        {
            ShowQrCode = true;
            SharedKey = FormatKey(pendingUser.AuthenticatorKey);
            AuthenticatorUri = GenerateAuthenticatorUri(pendingUser.Email, pendingUser.AuthenticatorKey);
            Message = "Forkert 2FA-kode. Brugeren er IKKE oprettet.";
            return Page();
        }

        var existingUser = await _userManager.FindByEmailAsync(pendingUser.Email);

        if (existingUser != null)
        {
            Message = "Brugeren findes allerede.";
            return Page();
        }

        var user = new ApplicationUser
        {
            UserName = pendingUser.Email,
            Email = pendingUser.Email,
            EmailConfirmed = true,
            CprNumber = _cprService.Hash(pendingUser.CprNumber)
        };

        var createResult = await _userManager.CreateAsync(user, pendingUser.Password);

        if (!createResult.Succeeded)
        {
            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            ShowQrCode = true;
            SharedKey = FormatKey(pendingUser.AuthenticatorKey);
            AuthenticatorUri = GenerateAuthenticatorUri(pendingUser.Email, pendingUser.AuthenticatorKey);
            Message = "2FA var korrekt, men brugeren kunne ikke oprettes. Ret fejlene og prøv igen.";

            return Page();
        }

        await _userManager.AddToRoleAsync(user, "Borger");

        var authenticatorStore = GetAuthenticatorKeyStore();

        await authenticatorStore.SetAuthenticatorKeyAsync(
            user,
            pendingUser.AuthenticatorKey,
            CancellationToken.None);

        await _userManager.SetTwoFactorEnabledAsync(user, true);

        HttpContext.Session.Remove(SessionKey);

        await _signInManager.SignInAsync(user, isPersistent: false);

        return RedirectToPage("/Borger/Index");
    }

    private IUserAuthenticatorKeyStore<ApplicationUser> GetAuthenticatorKeyStore()
    {
        if (_userStore is not IUserAuthenticatorKeyStore<ApplicationUser> authenticatorStore)
        {
            throw new NotSupportedException("UserStore understøtter ikke authenticator keys.");
        }

        return authenticatorStore;
    }

    private static string GenerateAuthenticatorUri(string email, string secret)
    {
        var encodedIssuer = Uri.EscapeDataString(Issuer);
        var encodedEmail = Uri.EscapeDataString(email);

        return $"otpauth://totp/{encodedIssuer}:{encodedEmail}?secret={secret}&issuer={encodedIssuer}&digits=6";
    }

    private static string GenerateBase32Secret()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        return Base32Encode(bytes);
    }

    private static string FormatKey(string key)
    {
        return string.Join(" ", Enumerable.Range(0, key.Length / 4)
            .Select(i => key.Substring(i * 4, 4)))
            .ToLowerInvariant();
    }

    private static bool VerifyTotpCode(string base32Secret, string code)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Length != 6)
        {
            return false;
        }

        var secretBytes = Base32Decode(base32Secret);
        var currentStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;

        for (var i = -1; i <= 1; i++)
        {
            var expectedCode = GenerateTotpCode(secretBytes, currentStep + i);

            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(expectedCode),
                    Encoding.UTF8.GetBytes(code)))
            {
                return true;
            }
        }

        return false;
    }

    private static string GenerateTotpCode(byte[] secret, long timestep)
    {
        var counter = BitConverter.GetBytes(timestep);

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counter);
        }

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counter);

        var offset = hash[^1] & 0x0F;

        var binaryCode =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);

        var otp = binaryCode % 1_000_000;

        return otp.ToString("D6");
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        var result = new StringBuilder();
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;

            while (bitsLeft >= 5)
            {
                result.Append(alphabet[(buffer >> (bitsLeft - 5)) & 31]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            result.Append(alphabet[(buffer << (5 - bitsLeft)) & 31]);
        }

        return result.ToString();
    }

    private static byte[] Base32Decode(string base32)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        var cleaned = base32.Replace(" ", "").ToUpperInvariant();
        var bytes = new List<byte>();

        var buffer = 0;
        var bitsLeft = 0;

        foreach (var c in cleaned)
        {
            var value = alphabet.IndexOf(c);

            if (value < 0)
            {
                continue;
            }

            buffer = (buffer << 5) | value;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 255));
                bitsLeft -= 8;
            }
        }

        return bytes.ToArray();
    }

    public class RegisterInput
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(10, MinimumLength = 10, ErrorMessage = "CPR skal være 10 cifre.")]
        [RegularExpression(@"^\d{10}$", ErrorMessage = "CPR må kun indeholde tal.")]
        public string CprNumber { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password og gentaget password matcher ikke.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class VerifyInput
    {
        [Required]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Koden skal være 6 cifre.")]
        public string Code { get; set; } = string.Empty;
    }

    private class PendingRegisterUser
    {
        public string Email { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string CprNumber { get; set; } = string.Empty;

        public string AuthenticatorKey { get; set; } = string.Empty;
    }
}