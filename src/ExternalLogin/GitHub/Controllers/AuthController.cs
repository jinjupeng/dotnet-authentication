using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace GitHub.Controllers
{
    /// <summary>
    /// GitHub第三方登录
    /// </summary>
    [Route("[controller]/[action]")]
    public class AuthController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl = "/")
        {
            return Challenge(new AuthenticationProperties() { RedirectUri = returnUrl });
        }
    }
}