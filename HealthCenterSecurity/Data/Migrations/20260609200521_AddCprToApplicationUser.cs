using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HealthCenterSecurity.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCprToApplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CprNumber",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CprNumber",
                table: "AspNetUsers");
        }
    }
}
