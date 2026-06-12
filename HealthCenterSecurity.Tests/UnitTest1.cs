using System.Reflection;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace HealthCenterSecurity.Tests;

public class SecurityTests
{
    private static Assembly WebAssembly => Assembly.Load("HealthCenterSecurity");
    private static Assembly ApiAssembly => Assembly.Load("HealthCenterSecurity.Api");

    [Fact]
    public void Backlog01_CprService_ShouldHashCprUsingProjectService()
    {
        // Arrange
        var service = CreateCprService();
        var serviceType = service.GetType();
        var cpr = "1234567890";

        // Act
        var hash = (string)serviceType.GetMethod("Hash")!.Invoke(service, [cpr])!;

        // Assert
        Assert.NotEqual(cpr, hash);
        Assert.True(hash.Length > 20);
    }

    [Fact]
    public void Backlog02_CprHash_ShouldBeDeterministic()
    {
        // Arrange
        var service = CreateCprService();
        var serviceType = service.GetType();
        var cpr = "1234567890";

        // Act
        var hash1 = (string)serviceType.GetMethod("Hash")!.Invoke(service, [cpr])!;
        var hash2 = (string)serviceType.GetMethod("Hash")!.Invoke(service, [cpr])!;

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void Backlog03_CprVerify_ShouldAcceptCorrectCpr()
    {
        // Arrange
        var service = CreateCprService();
        var serviceType = service.GetType();
        var cpr = "1234567890";
        var hash = (string)serviceType.GetMethod("Hash")!.Invoke(service, [cpr])!;

        // Act
        var isValid = (bool)serviceType.GetMethod("Verify")!.Invoke(service, [cpr, hash])!;

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void Backlog04_CprVerify_ShouldRejectWrongCpr()
    {
        // Arrange
        var service = CreateCprService();
        var serviceType = service.GetType();
        var realCpr = "1234567890";
        var wrongCpr = "9999999999";
        var hash = (string)serviceType.GetMethod("Hash")!.Invoke(service, [realCpr])!;

        // Act
        var isValid = (bool)serviceType.GetMethod("Verify")!.Invoke(service, [wrongCpr, hash])!;

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void Backlog05_PasskeyCredential_Model_ShouldExistInProject()
    {
        // Arrange
        var type = WebAssembly.GetTypes()
            .FirstOrDefault(t => t.Name == "PasskeyCredential");

        // Act
        var exists = type != null;

        // Assert
        Assert.True(exists);
    }

    [Fact]
    public void Backlog06_PasskeyCredential_ShouldContainRequiredProperties()
    {
        // Arrange
        var type = WebAssembly.GetTypes()
            .First(t => t.Name == "PasskeyCredential");

        // Act
        var propertyNames = type.GetProperties().Select(p => p.Name).ToList();

        // Assert
        Assert.Contains("UserId", propertyNames);
        Assert.Contains("CredentialId", propertyNames);
        Assert.Contains("PublicKey", propertyNames);
        Assert.Contains("SignatureCounter", propertyNames);
        Assert.Contains("CredType", propertyNames);
    }

    [Fact]
    public void Backlog07_ApplicationDbContext_ShouldContainPasskeyCredentialsDbSet()
    {
        // Arrange
        var dbContextType = WebAssembly.GetTypes()
            .First(t => t.Name == "ApplicationDbContext");

        // Act
        var hasPasskeyDbSet = dbContextType.GetProperties()
            .Any(p => p.Name == "PasskeyCredentials");

        // Assert
        Assert.True(hasPasskeyDbSet);
    }

    [Fact]
    public void Backlog08_PasskeyController_ShouldHaveRegisterBeginEndpoint()
    {
        // Arrange
        var controller = WebAssembly.GetTypes()
            .First(t => t.Name == "PasskeyController");

        // Act
        var methodExists = controller.GetMethods()
            .Any(m => m.Name == "RegisterBegin");

        // Assert
        Assert.True(methodExists);
    }

    [Fact]
    public void Backlog09_PasskeyController_ShouldHaveLoginCompleteEndpoint()
    {
        // Arrange
        var controller = WebAssembly.GetTypes()
            .First(t => t.Name == "PasskeyController");

        // Act
        var methodExists = controller.GetMethods()
            .Any(m => m.Name == "LoginComplete");

        // Assert
        Assert.True(methodExists);
    }

    [Fact]
    public void Backlog10_ApiDeleteEndpoint_ShouldRequireAdminRole()
    {
        // Arrange
        var usersController = ApiAssembly.GetTypes()
            .First(t => t.Name == "UsersController");

        var deleteMethod = usersController.GetMethods()
            .FirstOrDefault(m => m.GetCustomAttributes()
                .Any(a => a.GetType().Name == "HttpDeleteAttribute"));

        // Act
        var authorizeAttributes = usersController.GetCustomAttributes()
            .Concat(deleteMethod?.GetCustomAttributes() ?? [])
            .Where(a => a.GetType().Name == "AuthorizeAttribute")
            .ToList();

        var hasAdminAuthorize = authorizeAttributes.Any(attr =>
            attr.GetType().GetProperty("Roles")?.GetValue(attr)?.ToString() == "Admin");

        // Assert
        Assert.NotNull(deleteMethod);
        Assert.True(hasAdminAuthorize);
    }

    [Fact]
    public void Backlog11_SecureRegisterPage_ShouldExist()
    {
        // Arrange
        var pageModel = WebAssembly.GetTypes()
            .FirstOrDefault(t => t.Name == "SecureRegisterModel");

        // Act
        var exists = pageModel != null;

        // Assert
        Assert.True(exists);
    }

    [Fact]
    public void Backlog12_SecureRegister_ShouldHaveStartAndVerifyHandlers()
    {
        // Arrange
        var pageModel = WebAssembly.GetTypes()
            .First(t => t.Name == "SecureRegisterModel");

        // Act
        var methods = pageModel.GetMethods().Select(m => m.Name).ToList();

        // Assert
        Assert.Contains("OnPostStartAsync", methods);
        Assert.Contains("OnPostVerifyAsync", methods);
    }

    [Fact]
    public void Backlog13_Program_ShouldConfigurePasswordPolicyAndLockout()
    {
        // Arrange
        var programText = File.ReadAllText(GetWebProjectFile("Program.cs"));

        // Act
        var hasPasswordPolicy =
            programText.Contains("options.Password.RequiredLength = 10") &&
            programText.Contains("options.Password.RequireUppercase = true") &&
            programText.Contains("options.Password.RequireDigit = true") &&
            programText.Contains("options.Password.RequireNonAlphanumeric = true");

        var hasLockout =
            programText.Contains("options.Lockout.MaxFailedAccessAttempts = 5") &&
            programText.Contains("TimeSpan.FromMinutes(5)");

        // Assert
        Assert.True(hasPasswordPolicy);
        Assert.True(hasLockout);
    }

    [Fact]
    public void Backlog14_Program_ShouldConfigureSecureCookies()
    {
        // Arrange
        var programText = File.ReadAllText(GetWebProjectFile("Program.cs"));

        // Act
        var hasSecureCookies =
            programText.Contains("options.Cookie.HttpOnly = true") &&
            programText.Contains("CookieSecurePolicy.Always") &&
            programText.Contains("SameSiteMode.Strict");

        // Assert
        Assert.True(hasSecureCookies);
    }

    [Fact]
    public void Backlog15_AppSettings_ShouldConfigureHttpsCertificate()
    {
        // Arrange
        var appsettings = new ConfigurationBuilder()
            .AddJsonFile(GetWebProjectFile("appsettings.json"))
            .Build();

        // Act
        var url = appsettings["Kestrel:Endpoints:Https:Url"];
        var certificatePath = appsettings["Kestrel:Endpoints:Https:Certificate:Path"];

        // Assert
        Assert.Equal("https://localhost:7070", url);
        Assert.Equal("localhost-healthcenter.pfx", certificatePath);
    }

    private static object CreateCprService()
    {
        var serviceType = WebAssembly.GetTypes()
            .First(t => t.FullName == "HealthCenterSecurity.Services.CprEncryptionService");

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CprEncryptionKey"] = "MinMegetHemmeligeCPRNogle123!"
            })
            .Build();

        return Activator.CreateInstance(serviceType, configuration)!;
    }

    private static string GetWebProjectFile(string fileName)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory != null)
        {
            var candidate = Path.Combine(directory.FullName, "HealthCenterSecurity", fileName);

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException($"Kunne ikke finde {fileName}");
    }
}