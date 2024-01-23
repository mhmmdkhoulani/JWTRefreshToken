using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JsonWebToken.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetDate()
        {
            var data  = new List<string>();
            data.Add("Rami");
            data.Add("Mohammad");
            data.Add("Saeed");
            data.Add("Majdy");
            data.Add("Rama");

            return Ok(data);
        }
    }
}
