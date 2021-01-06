using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Server.Controllers
{
    public class OAuthController : Controller
    {
        /*
         * https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type
         * 授权码模式：
         * 1、用户访问客户端，后者将前者导向认证服务器。
         * 2、用户选择是否给予客户端授权。
         * 3、假设用户给予授权，认证服务器将用户导向客户端事先指定的"重定向URI"（redirection URI），同时附上一个授权码。
         * 4、客户端收到授权码，附上早先的"重定向URI"，向认证服务器申请令牌。这一步是在客户端的后台的服务器上完成的，对用户不可见。
         * 5、认证服务器核对了授权码和重定向URI，确认无误后，向客户端发送访问令牌（access token）和更新令牌（refresh token）。
         */

        /// <summary>
        /// 授权：授权码模式
        /// 向客户端授权
        /// </summary>
        /// <param name="response_type">授权类型，必选项authorization flow type </param>
        /// <param name="client_id">客户端的id，必选项client id</param>
        /// <param name="redirect_uri">重定向url，可选项</param>
        /// <param name="scope">申请的权限范围，可选项what info I want = email,grandma,tel</param>
        /// <param name="state">客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值random string generated to confirm that we are going to back to the same client</param>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Authorize(
            string response_type, // authorization flow type 
            string client_id, // client id
            string redirect_uri,
            string scope, // what info I want = email,grandma,tel
            string state) // random string generated to confirm that we are going to back to the same client
        {
            // ?a=foo&b=bar
            var query = new QueryBuilder
            {
                { "redirectUri", redirect_uri },
                { "state", state }
            };

            return View(model: query.ToString());
        }

        /// <summary>
        /// 向客户端授权，并重定向url同时附加一个授权码code
        /// </summary>
        /// <param name="username"></param>
        /// <param name="redirectUri">重定向url，必选项</param>
        /// <param name="state">如果客户端的请求中包含这个参数，认证服务器的回应也必须一模一样包含这个参数</param>
        /// <returns></returns>
        [HttpPost]
        public IActionResult Authorize(
            string username, // 在这里好像没用
            string redirectUri,
            string state)
        {
            // 授权码，有效期一般在10分钟以内，客户端只能使用该码一次
            // 这里是写死的
            const string code = "BABAABABABA";

            var query = new QueryBuilder
            {
                { "code", code },
                { "state", state }
            };

            // 重定向
            return Redirect($"{redirectUri}{query}");
        }

        /// <summary>
        /// 认证服务器核对了授权码和重定向URI，确认无误后，向客户端发送访问令牌（access token）和更新令牌（refresh token）
        /// </summary>
        /// <param name="grant_type">授权模式flow of access_token request</param>
        /// <param name="code">授权码confirmation of the authentication process</param>
        /// <param name="redirect_uri">重定向url</param>
        /// <param name="client_id">客户端id</param>
        /// <param name="refresh_token">更新令牌，用来获取下一次的访问令牌，可选项</param>
        /// <returns>重定向</returns>
        public async Task<IActionResult> Token(
            string grant_type, // flow of access_token request
            string code, // confirmation of the authentication process
            string redirect_uri,
            string client_id,
            string refresh_token)
        {
            // some mechanism for validating the code

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                // 自定义
                new Claim("granny", "cookie")
            };

            var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            var key = new SymmetricSecurityKey(secretBytes);
            var algorithm = SecurityAlgorithms.HmacSha256;

            var signingCredentials = new SigningCredentials(key, algorithm);

            var token = new JwtSecurityToken(
                Constants.Issuer,
                Constants.Audiance,
                claims,
                notBefore: DateTime.Now,
                expires: grant_type == "refresh_token"
                    ? DateTime.Now.AddMinutes(5)
                    : DateTime.Now.AddMilliseconds(1),
                signingCredentials);

            var access_token = new JwtSecurityTokenHandler().WriteToken(token);

            // 向前端返回访问令牌（access_token）和更新令牌（refresh_token）
            var responseObject = new
            {
                access_token,
                token_type = "Bearer",
                raw_claim = "oauthTutorial",
                refresh_token = "RefreshTokenSampleValueSomething77"
            };

            var responseJson = JsonConvert.SerializeObject(responseObject);
            var responseBytes = Encoding.UTF8.GetBytes(responseJson);

            await Response.Body.WriteAsync(responseBytes, 0, responseBytes.Length);

            return Redirect(redirect_uri);
        }

        /// <summary>
        /// 验证token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Validate()
        {
            if (HttpContext.Request.Query.TryGetValue("access_token", out var accessToken))
            {
                // to do something
                return Ok();
            }
            return BadRequest();
        }
    }
}
