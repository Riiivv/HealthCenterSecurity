using Fido2NetLib;
using Fido2NetLib.Objects;
using HealthCenterSecurity.Data;
using HealthCenterSecurity.Models;
using HealthCenterSecurity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace HealthCenterSecurity.Controllers;

[ApiController]
[Route("passkey")]
public class PasskeyController : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly ApplicationDbContext _context;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly CprEncryptionService _cprService;

    public PasskeyController(
        IFido2 fido2,
        ApplicationDbContext context,
        SignInManager<ApplicationUser> signInManager,
        CprEncryptionService cprService)
    {
        _fido2 = fido2;
        _context = context;
        _signInManager = signInManager;
        _cprService = cprService;
    }

    [HttpPost("register/begin")]
    public async Task<IActionResult> RegisterBegin([FromBody] PasskeyRegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
        {
            return BadRequest("Email mangler.");
        }

        if (string.IsNullOrWhiteSpace(request.CprNumber))
        {
            return BadRequest("CPR-nummer mangler.");
        }

        if (request.CprNumber.Length != 10 || !request.CprNumber.All(char.IsDigit))
        {
            return BadRequest("CPR-nummer skal være præcis 10 cifre.");
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Username);

        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = request.Username,
                Email = request.Username,
                EmailConfirmed = true,
                CprNumber = _cprService.Hash(request.CprNumber)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var borgerRole = await _context.Roles.FirstOrDefaultAsync(r => r.Name == "Borger");

            if (borgerRole != null)
            {
                _context.UserRoles.Add(new IdentityUserRole<string>
                {
                    UserId = user.Id,
                    RoleId = borgerRole.Id
                });

                await _context.SaveChangesAsync();
            }
        }
        else
        {
            return BadRequest("Brugeren findes allerede.");
        }

        var fidoUser = new Fido2User
        {
            Id = Encoding.UTF8.GetBytes(user.Id),
            Name = user.Email!,
            DisplayName = user.Email!
        };

        var existingCredentials = await _context.PasskeyCredentials
            .Where(c => c.UserId == user.Id)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync();

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = fidoUser,
            ExcludeCredentials = existingCredentials,
            AuthenticatorSelection = AuthenticatorSelection.Default,
            AttestationPreference = AttestationConveyancePreference.None
        });

        HttpContext.Session.SetString("fido2.register", options.ToJson());
        HttpContext.Session.SetString("fido2.userId", user.Id);

        return Ok(options);
    }

    [HttpPost("register/complete")]
    public async Task<IActionResult> RegisterComplete([FromBody] AuthenticatorAttestationRawResponse attestation)
    {
        var json = HttpContext.Session.GetString("fido2.register");
        var userId = HttpContext.Session.GetString("fido2.userId");

        if (json == null || userId == null)
        {
            return BadRequest("Session udløbet.");
        }

        var options = CredentialCreateOptions.FromJson(json);

        IsCredentialIdUniqueToUserAsyncDelegate callback = async (args, cancellationToken) =>
        {
            return !await _context.PasskeyCredentials
                .AnyAsync(c => c.CredentialId == args.CredentialId, cancellationToken);
        };

        var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestation,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = callback
        });

        _context.PasskeyCredentials.Add(new PasskeyCredential
        {
            UserId = userId,
            CredentialId = result.Id,
            PublicKey = result.PublicKey,
            SignatureCounter = result.SignCount,
            CredType = "public-key"
        });

        await _context.SaveChangesAsync();

        return Ok(new { message = "Passkey registreret." });
    }

    [HttpPost("login/begin")]
    public async Task<IActionResult> LoginBegin([FromBody] UsernameRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Username);

        if (user == null)
        {
            return BadRequest("Brugeren findes ikke.");
        }

        var credentials = await _context.PasskeyCredentials
            .Where(c => c.UserId == user.Id)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync();

        if (!credentials.Any())
        {
            return BadRequest("Brugeren har ingen passkey registreret.");
        }

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = credentials,
            UserVerification = UserVerificationRequirement.Preferred
        });

        HttpContext.Session.SetString("fido2.login", options.ToJson());
        HttpContext.Session.SetString("fido2.loginUserId", user.Id);

        return Ok(options);
    }

    [HttpPost("login/complete")]
    public async Task<IActionResult> LoginComplete([FromBody] AuthenticatorAssertionRawResponse assertion)
    {
        var json = HttpContext.Session.GetString("fido2.login");
        var userId = HttpContext.Session.GetString("fido2.loginUserId");

        if (json == null || userId == null)
        {
            return BadRequest("Session udløbet.");
        }

        var options = AssertionOptions.FromJson(json);

        var allCredentials = await _context.PasskeyCredentials.ToListAsync();

        var credential = allCredentials
            .FirstOrDefault(c => c.CredentialId.SequenceEqual(assertion.RawId));

        if (credential == null)
        {
            return BadRequest("Ukendt passkey credential.");
        }

        IsUserHandleOwnerOfCredentialIdAsync callback = async (args, cancellationToken) =>
        {
            if (args.UserHandle == null || args.UserHandle.Length == 0)
            {
                return credential.UserId == userId &&
                       credential.CredentialId.SequenceEqual(args.CredentialId);
            }

            var decodedUserId = Encoding.UTF8.GetString(args.UserHandle);

            return await _context.PasskeyCredentials
                .AnyAsync(c =>
                    c.UserId == decodedUserId &&
                    c.CredentialId.SequenceEqual(args.CredentialId),
                    cancellationToken);
        };

        var result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertion,
            OriginalOptions = options,
            StoredPublicKey = credential.PublicKey,
            StoredSignatureCounter = credential.SignatureCounter,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        });

        credential.SignatureCounter = result.SignCount;
        await _context.SaveChangesAsync();

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
        {
            return BadRequest("Brugeren findes ikke længere.");
        }

        await _signInManager.SignInAsync(user, isPersistent: false);

        return Ok(new { redirectUrl = "/Borger" });
    }
}

public record UsernameRequest(string Username);

public record PasskeyRegisterRequest(string Username, string CprNumber);