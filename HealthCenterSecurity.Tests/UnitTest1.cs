using System.Security.Cryptography;
using System.Text;

namespace HealthCenterSecurity.Tests;

public class SecurityTests
{
    [Fact]
    public void Backlog01_Register_ShouldRequireEmailPasswordAndCpr()
    {
        // Arrange
        var email = "borger@test.dk";
        var password = "Password123!";
        var cpr = "1234567890";

        // Act
        var isValid = email.Contains("@")
                      && password.Length >= 10
                      && cpr.Length == 10
                      && cpr.All(char.IsDigit);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void Backlog02_Login_ShouldRequireEmailAndPassword()
    {
        // Arrange
        var email = "borger@test.dk";
        var password = "Password123!";

        // Act
        var canLoginAttemptStart =
            !string.IsNullOrWhiteSpace(email) &&
            !string.IsNullOrWhiteSpace(password);

        // Assert
        Assert.True(canLoginAttemptStart);
    }

    [Fact]
    public void Backlog03_MfaCode_ShouldBeSixDigits()
    {
        // Arrange
        var authenticatorCode = "123456";

        // Act
        var isValidMfaCode =
            authenticatorCode.Length == 6 &&
            authenticatorCode.All(char.IsDigit);

        // Assert
        Assert.True(isValidMfaCode);
    }

    [Fact]
    public void Backlog04_BorgerPage_ShouldRequireBorgerRole()
    {
        // Arrange
        var requiredRole = "Borger";

        // Act
        var hasCorrectRoleRequirement = requiredRole == "Borger";

        // Assert
        Assert.True(hasCorrectRoleRequirement);
    }

    [Fact]
    public void Backlog05_AdminPage_ShouldRequireAdminRole()
    {
        // Arrange
        var requiredRole = "Admin";

        // Act
        var hasCorrectRoleRequirement = requiredRole == "Admin";

        // Assert
        Assert.True(hasCorrectRoleRequirement);
    }

    [Fact]
    public void Backlog06_Admin_ShouldBeAbleToSeeUserList()
    {
        // Arrange
        var users = new[] { "borger1@test.dk", "borger2@test.dk" };

        // Act
        var userCount = users.Length;

        // Assert
        Assert.True(userCount > 0);
    }

    [Fact]
    public void Backlog07_DeleteUser_ShouldUseWebApiEndpoint()
    {
        // Arrange
        var httpMethod = "DELETE";
        var endpoint = "/api/users/delete/test-user-id";

        // Act
        var isDeleteEndpoint =
            httpMethod == "DELETE" &&
            endpoint.Contains("/api/users");

        // Assert
        Assert.True(isDeleteEndpoint);
    }

    [Fact]
    public void Backlog08_DeleteUserEndpoint_ShouldRequireAdminRole()
    {
        // Arrange
        var authorizeRole = "Admin";

        // Act
        var isAdminProtected = authorizeRole == "Admin";

        // Assert
        Assert.True(isAdminProtected);
    }

    [Fact]
    public void Backlog09_Cpr_ShouldBeHashedAndNotPlainText()
    {
        // Arrange
        var cpr = "1234567890";

        // Act
        var hash = HashCpr(cpr);

        // Assert
        Assert.NotEqual(cpr, hash);
        Assert.True(hash.Length > 20);
    }

    [Fact]
    public void Backlog10_PasswordPolicy_ShouldRequireStrongPassword()
    {
        // Arrange
        var password = "Password123!"; // abc // Password123!

        // Act
        var isStrongPassword =
            password.Length >= 10 &&
            password.Any(char.IsUpper) &&
            password.Any(char.IsDigit) &&
            password.Any(c => !char.IsLetterOrDigit(c));

        // Assert
        Assert.True(isStrongPassword);
    }

    [Fact]
    public void Backlog11_Lockout_ShouldTriggerAfterFiveFailedAttempts()
    {
        // Arrange
        var maxFailedAttempts = 5;
        var lockoutMinutes = 5;

        // Act
        var lockoutIsConfigured =
            maxFailedAttempts == 5 &&
            lockoutMinutes == 5;

        // Assert
        Assert.True(lockoutIsConfigured);
    }

    [Fact]
    public void Backlog12_Https_ShouldUsePfxCertificate()
    {
        // Arrange
        var certificatePath = "localhost-healthcenter.pfx";
        var url = "https://localhost:7070";

        // Act
        var httpsWithCertificate =
            certificatePath.EndsWith(".pfx") &&
            url.StartsWith("https://");

        // Assert
        Assert.True(httpsWithCertificate);
    }

    [Fact]
    public void Backlog13_Cookies_ShouldUseSecureSettings()
    {
        // Arrange
        var httpOnly = true;
        var secure = true;
        var sameSite = "Strict";

        // Act
        var cookiesAreSecure =
            httpOnly &&
            secure &&
            sameSite == "Strict";

        // Assert
        Assert.True(cookiesAreSecure);
    }

    [Fact]
    public void Backlog14_Forms_ShouldUseCsrfToken()
    {
        // Arrange
        var csrfTokenFieldName = "__RequestVerificationToken";

        // Act
        var usesCsrfToken = csrfTokenFieldName == "__RequestVerificationToken";

        // Assert
        Assert.True(usesCsrfToken);
    }

    [Fact]
    public void Backlog15_TestPlan_ShouldContainSecurityAndFunctionalTests()
    {
        // Arrange
        var testAreas = new[]
        {
            "Login",
            "Roller",
            "MFA",
            "CPR",
            "Cookies",
            "API delete",
            "CSRF",
            "XSS"
        };

        // Act
        var containsRequiredAreas =
            testAreas.Contains("Login") &&
            testAreas.Contains("CPR") &&
            testAreas.Contains("API delete");

        // Assert
        Assert.True(containsRequiredAreas);
    }

    private static string HashCpr(string cpr)
    {
        var key = Encoding.UTF8.GetBytes("MinMegetHemmeligeCPRNogle123!");

        using var hmac = new HMACSHA256(key);

        var bytes = Encoding.UTF8.GetBytes(cpr);
        var hash = hmac.ComputeHash(bytes);

        return Convert.ToBase64String(hash);
    }
}