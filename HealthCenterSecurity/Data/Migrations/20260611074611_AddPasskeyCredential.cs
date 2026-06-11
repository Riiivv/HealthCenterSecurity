using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HealthCenterSecurity.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPasskeyCredential : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Transports",
                table: "PasskeyCredentials");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "PasskeyCredentials",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<DateTime>(
                name: "CreatedAt",
                table: "PasskeyCredentials",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "CredType",
                table: "PasskeyCredentials",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_PasskeyCredentials_UserId",
                table: "PasskeyCredentials",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_PasskeyCredentials_AspNetUsers_UserId",
                table: "PasskeyCredentials",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PasskeyCredentials_AspNetUsers_UserId",
                table: "PasskeyCredentials");

            migrationBuilder.DropIndex(
                name: "IX_PasskeyCredentials_UserId",
                table: "PasskeyCredentials");

            migrationBuilder.DropColumn(
                name: "CreatedAt",
                table: "PasskeyCredentials");

            migrationBuilder.DropColumn(
                name: "CredType",
                table: "PasskeyCredentials");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "PasskeyCredentials",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AddColumn<string>(
                name: "Transports",
                table: "PasskeyCredentials",
                type: "nvarchar(max)",
                nullable: true);
        }
    }
}
