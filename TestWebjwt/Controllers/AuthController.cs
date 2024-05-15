using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestWebjwt.Models;
using TestWebjwt.Services;

namespace TestWebjwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> register([FromBody]RegisterModel model)
        {
            if(!ModelState.IsValid) 
                return BadRequest(ModelState);

            var result= await _authService.Register(model);
            if(!result.IsAuthenticated) 
                return BadRequest(result.Messege);

            return Ok(result);

        }

        [HttpPost("Token")]
        public async Task<IActionResult> GetToken([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.GetToken(model);
            if (!result.IsAuthenticated)
                return BadRequest(result.Messege);

            return Ok(result);

        }

        [HttpPost("Addrole")]
        public async Task<IActionResult> AddRole([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddRole(model);
            if (! string.IsNullOrEmpty(result) )
                return BadRequest(result);

            return Ok(model);

        }
    }
}
