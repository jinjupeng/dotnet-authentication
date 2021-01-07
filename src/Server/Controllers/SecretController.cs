using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
{
    public class SecretController : Controller
    {
        /*
         * Server作为OAuth2授权服务器，当授权通过后，Client端就会访问这个页面获取到授权人信息
         */

        // [Authorize]
        [Authorize(Policy = "ValidAccessToken")]
        public string Index()
        {
            return "secret message";
        }

    }
}
