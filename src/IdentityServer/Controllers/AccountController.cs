using IdentityServer.ViewModels;
using IdentityServer4;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly TestUserStore _users;
        public AccountController(TestUserStore users)
        {
            _users = users;
        }

        /// <summary>
        /// 内部跳转
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                //如果是本地
                return Redirect(returnUrl);
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        public IActionResult Register()
        {
            return View();
        }

        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                ViewData["returnUrl"] = returnUrl;

                //var user = await _userManager.FindByEmailAsync(loginViewModel.Email);
                var user = _users.FindByUsername(loginViewModel.UserName);

                if (user == null)
                {
                    ModelState.AddModelError(nameof(loginViewModel.UserName), "UserName not exists");
                }
                else
                {
                    if (_users.ValidateCredentials(loginViewModel.UserName, loginViewModel.Password))
                    {
                        // issue authentication cookie with subject ID and username
                        var isuser = new IdentityServerUser(user.SubjectId)
                        {
                            DisplayName = user.Username,
                        };
                        //是否记住
                        var prop = new AuthenticationProperties()
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(TimeSpan.FromMinutes(30))
                        };

                        await AuthenticationManagerExtensions.SignInAsync(HttpContext, isuser, prop);
                    }
                }
                //账号密码先不做验证，需要可以自己写
                //await _signInManager.SignInAsync(user, new AuthenticationProperties { IsPersistent = true });

                return RedirectToLocal(returnUrl);
            }

            return View();

        }

        /// <summary>
        /// 添加验证错误
        /// </summary>
        /// <param name="result"></param>
        private void AddError(IdentityResult result)
        {
            //遍历所有的验证错误
            foreach (var error in result.Errors)
            {
                //返回error到model
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }


        /// <summary>
        /// 登陆
        /// </summary>
        /// <returns></returns>
        public IActionResult MakeLogin()
        {
            var claims = new List<Claim>(){
                new Claim(ClaimTypes.Name,"username"),
                new Claim(ClaimTypes.Role,"admin")
            };

            var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimIdentity));

            return Ok();
        }

        /// <summary>
        /// 登出
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
