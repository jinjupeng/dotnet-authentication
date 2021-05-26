using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers
{
    /// <summary>
    /// 受保护的资源
    /// </summary>
    public class SecretController : Controller
    {
        [Authorize]
        public string Index()
        {
            return "secret message";
        }
    }
}
