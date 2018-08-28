using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class tokenController : ControllerBase
    {
        private IConfiguration _config;

        public tokenController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        //public IActionResult CreateToken([FromBody]LoginModel login)
        public IActionResult CreateToken()
        {
            var userId = HttpContext.User.Identity.Name;

            IActionResult response = Unauthorized();
            var user = Authenticate(new LoginModel { Username = HttpContext.User.Identity.Name, Password = "Ciccio" });

            if (user != null)
            {
                var tokenString = BuildToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        [HttpGet("IsAdmin"), Authorize]
        public async Task<bool> IsAdmin()
        {
            var userId = HttpContext.User.Identity.Name;
            //base.logger.Info($"Windows User for request : {userId}");

            // TODO inserire il controllo di dominio!!!!! DB/LDAP/ActiveDirectory
            return true;
        }

        private string BuildToken(UserModel user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel Authenticate(LoginModel login)
        {
            UserModel user = null;

            if (login.Username == "LAPTOP-4SCOMA6I\\UCCIARDI Giovanni" && login.Password == "Ciccio")
            {
                user = new UserModel { Name = "Mario Rossi", Email = "mario.rossi@domain.com" };
            }
            return user;
        }

        public class LoginModel
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        private class UserModel
        {
            public string Name { get; set; }
            public string Email { get; set; }
            public DateTime Birthdate { get; set; }
        }
    }
}