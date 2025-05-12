namespace Lensisku.Auth.DTOs
{
    // This DTO is used to transfer information about a permission,
    // typically its name and description.
    public class PermissionInfoDto
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
    }
}