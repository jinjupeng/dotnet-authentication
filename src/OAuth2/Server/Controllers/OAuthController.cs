using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Server.Controllers
{
    /// <summary>
    /// OAuth2授权
    /// </summary>
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
        public IActionResult Authorize(string username, string redirectUri, string state)
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
        /// <returns></returns>
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

        /*
         * https://juejin.cn/post/6847009773477429255
         * OAuth2.0 授权过程中几个重要的参数:
         * 1、response_type：code 表示要求返回授权码，token 表示直接返回令牌
         * 2、client_id：客户端身份标识
         * 3、client_secret：客户端密钥
         * 4、redirect_uri：重定向地址
         * 5、scope：表示授权的范围，read只读权限，all读写权限
         * 6、grant_type：表示授权的方式，AUTHORIZATION_CODE（授权码）、password（密码）、client_credentials（凭证式）、refresh_token 更新令牌
         * 7、state：应用程序传递的一个随机数，用来防止CSRF攻击
         */

        /// <summary>
        /// 用于颁发客户端凭据 （客户端 ID 和客户端密钥）
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("Credentials ")]
        public async Task<IActionResult> Credentials()
        {
            var clientId = Guid.NewGuid().ToString("N");
            var clientSecret = Guid.NewGuid().ToString("N");
            var json = new
            {
                CLIENT_ID = clientId,
                CLIENT_SECRET = clientSecret
            };
            return Ok(await Task.FromResult(json));
        }

        /// <summary>
        /// 使用客户端凭据颁发令牌
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("Token ")]
        public async Task<IActionResult> Token()
        {
            // 获取clientId、clientSecret
            return Ok(await Task.FromResult(""));
        }

        #region 授权码模式（authorization-code）

        [HttpGet]
        public IActionResult Authorize(string client_id,
            string redirect_uri, string scope)
        {
            var client = GetClients().Any(a => a.client_id == client_id);
            if (!client)
            {
                Console.WriteLine($"Unknown client{client_id}");
                return View("error"); // 返回到错误页面
            }

        }

        #endregion

        #region 隐式授权模式（implicit）

        #endregion

        #region 客户端验证模式（client credentials）

        #endregion

        #region 密码模式（password）

        #endregion

        /// <summary>
        /// 客户端集合
        /// </summary>
        /// <returns></returns>
        private List<Client> GetClients()
        {
            var clients = new List<Client> {
                new Client
                {
                     client_id = "oauth-client-1",
                     client_secret = "oauth-client-secret-1",
                     redirect_uris = new string[] { "http://localhost:9000/callback" },
                     scope = "foo bar",
                     logo_uri = "https://images.manning.com/720/960/resize/book/e/14336f9-6493-46dc-938c-11a34c9d20ac/Richer-OAuth2-HI.png",
                     client_name = "OAuth in Action Exercise Client"
                },
                new Client
                {
                     client_id = "oauth-client-2",
                     client_secret = "oauth-client-secret-1",
                     redirect_uris = new string[] { "http://localhost:9000/callback" },
                     scope = "bar"
                },
                new Client
                {
                     client_id = "native-client-1",
                     client_secret = "oauth-native-secret-1",
                     redirect_uris = new string[] { "mynativeapp://" },
                     scope = "openid profile email phone address",
                     logo_uri = "https://images.manning.com/720/960/resize/book/e/14336f9-6493-46dc-938c-11a34c9d20ac/Richer-OAuth2-HI.png"
                },
            };
            return clients;
        }
    }
}
