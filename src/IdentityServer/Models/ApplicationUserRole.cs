using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Models
{
    public class ApplicationUserRole : IdentityRole<int>//不加int的话是默认主键为guid
    {
    }
}
