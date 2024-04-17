using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using ServerLibrary.Repositories.Contracts;
using System.Threading.Tasks;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IUserAccount accountInterface) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> Create(Register user)
        {
            if (user == null) return BadRequest("Model is empty");
            var result = await accountInterface.Create(user);
            return Ok(result);
        }
        
        [HttpPost("login")]
        public async Task<IActionResult> SignIn(Login user)
        {
            if (user == null) return BadRequest("Model is empty");
            var result = await accountInterface.SignIn(user);
            return Ok(result);
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshToken token)
        {
            if (token == null) return BadRequest("Model is empty");
            var result = await accountInterface.RefreshToken(token);
            return Ok(result);
        }

    }
}
