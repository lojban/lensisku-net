// Data Transfer Objects (DTOs) are simple classes used to transfer data between layers,
// especially between the service layer and the presentation layer (controllers), or over the network.
// They help to decouple service layer logic from database models and shape data specifically for API contracts.
using System.ComponentModel.DataAnnotations;

namespace Lensisku.Auth.DTOs
{
    public class EmailConfirmationRequestDto
    {
        // [Required] attribute is a validation attribute indicating that this property must have a value.
        [Required]
        public string Token { get; set; } = string.Empty;
    }
}