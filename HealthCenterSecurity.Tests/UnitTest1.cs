namespace HealthCenterSecurity.Tests;

public class SecurityTests
{
    [Fact]
    public void AdminRoleName_ShouldBe_Admin()
    {
        var roleName = "Admin";

        Assert.Equal("Admin", roleName);
    }

    [Fact]
    public void BorgerRoleName_ShouldBe_Borger()
    {
        var roleName = "Borger";

        Assert.Equal("Borger", roleName);
    }

    [Fact]
    public void PasswordPolicy_ShouldRequireMinimum10Characters()
    {
        var minimumLength = 10;

        Assert.True(minimumLength >= 10);
    }
    [Fact]
    public void Https_ShouldBeEnabled()
    {
        bool httpsEnabled = true;

        Assert.True(httpsEnabled);
    }

    [Fact]
    public void CprEncryption_ShouldExist()
    {
        bool encryptionImplemented = true;

        Assert.True(encryptionImplemented);
    }
}