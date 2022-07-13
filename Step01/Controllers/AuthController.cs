using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Step01.ViewModels;

namespace Step01.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    [HttpPost()]
    public ActionResult Login(LoginViewModel model){
        if (model.UserName == "kalle" && model.Password == "Pa$$w0rd" )
        {
            return Ok(new {
                access_token = CreateJwtToken(model.UserName)
            });
        }
        return Unauthorized();
    }

    private string CreateJwtToken(string UserName){
        var claims = new List<Claim>{
            new Claim(ClaimTypes.Country, "Sweden"),
            new Claim(ClaimTypes.Email, "kalle@gmail.com"),
            new Claim("User", "true")
        };
        var key = Encoding.ASCII.GetBytes("lsakjdfdvjldktjkhbkldlsmtnjönvjhbtuyaberyh tbrnb zci");
        var jwt = new JwtSecurityToken(
            claims: claims,
            notBefore: DateTime.Now,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha512Signature
            )
        );
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}