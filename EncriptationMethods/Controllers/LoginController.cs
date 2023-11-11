using EncriptationMethods.Models;
using EncriptationMethods.Resources;
using EncriptationMethods.Services.Contract;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace EncriptationMethods.Controllers
{
    public class LoginController : Controller
    {
        private readonly IUserService _userService;

        public LoginController(IUserService userService)
        {
            _userService = userService;
        }

        public IActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(User user)
        {
            string[] llavesCifrado = Utility.GenerateKeys();
            user.PrivateKey = llavesCifrado[1];

            // Validations
            if (!ModelState.IsValid)
            {
                return View();
            }

            User foundUser = await _userService.GetUserByEmail(user.Email);
            if(foundUser != null)
            {
                ViewData["Message"] = "This email is already registerd";
                return View();
            }

            string cifrado = Utility.EncryptPasswordAsymmetrically(user.Password, llavesCifrado[0]);

            // Create User
            user.Password = cifrado;
            user.PrivateKey = llavesCifrado[1];
            User userCreated = await _userService.SaveUser(user);

            if(userCreated.IdUsuario > 0)
            {
                return RedirectToAction("Login", "Login");
            }

            ViewData["Message"] = "User has not been created";

            return View();
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {

            if(!ModelState.IsValid)
            {
                return View();
            }

            User? user = await _userService.GetUserByEmail(email);

            if (user == null)
            {
                ViewData["Message"] = "This user not exist";
                return View();
            }

            string[] llavesCifrado = Utility.GenerateKeys();
            string claveDesifrada = Utility.DecryptPassword(user.Password, user.PrivateKey);

            if (password != claveDesifrada)
            {
                ViewData["Message"] = "The email or password are not valid";
                return View();
            }

            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            AuthenticationProperties properties = new AuthenticationProperties()
            {
                AllowRefresh = true
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                properties
                );

            return RedirectToAction("Index", "Home");
        }
    }
}
