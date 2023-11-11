using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Configuration;

namespace EncriptationMethods.Models
{
    public class User
    {
        [Key]
        public int IdUsuario { get; set; }

        [Required]
        [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "The username cannot contain numbers or symbols")]
        public string Username { get; set; }

        [Required]
        [EmailAddress(ErrorMessage = "This email is not valid")]
        public string Email { get; set; }

        [Required]
        [StringLength(10, ErrorMessage = "The phone number must be 10 characters long")]
        public string Telephone { get; set; }

        [Required]
        [RegularExpression(@"^(?=.*[a-zA-Z])(?=.*\d).+", ErrorMessage = "The password must contain letters and numbers")]
        [MinLength(10, ErrorMessage = "The password must be 10 characters long")]
        public string Password { get; set; }

        [DefaultValue("")]
        public string? PrivateKey { get; set; }
    }
}
