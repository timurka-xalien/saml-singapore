using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using CumulusPro.Saml.Prototype.Models;
using CumulusPro.Saml.Prototype.Services;
using CumulusPro.Saml.Prototype.Services.Services;
using NLog;

namespace CumulusPro.Saml.Prototype.Controllers
{
    [Authorize]
    public partial class AccountController : Controller
    {
        private Logger _logger = LogManager.GetCurrentClassLogger();

        private AuthenticationService _authenticationService;

        public AccountController()
        {
            _authenticationService = new AuthenticationService(AuthenticationManager, UserManager);
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
            : this()
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            ViewBag.IdentityProviders = SamlIdentityProvidersRepository.GetRegisteredIdentityProviders();
            return View();
        }

        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check if we need to login user locally (in case no SAML Identity Provider is registered for specified email domain)
            var emailDomain = Utils.GetEmailDomain(model.Email);
            var isSamlAuthenticationRequired =
                SamlIdentityProvidersRepository.IsSamlAuthenticationRequired(emailDomain);

            if (isSamlAuthenticationRequired)
            {
                _logger.Log(LogLevel.Debug, $"SAML: AccountController.Login: Log in user {model.Email} via SAML SSO.");

                // Get appropriate IdP entity id
                var idpEntityId = SamlIdentityProvidersRepository.GetIdentityProviderEntityId(emailDomain);

                if (idpEntityId == null)
                {
                    _logger.Log(LogLevel.Warn, $"SAML: SamlController.SingleSignOn: IdP for domain {emailDomain} not found.");

                    return View("Error");
                }

                _logger.Log(LogLevel.Debug, $"SAML: AccountController.Login: Redirecting user to {idpEntityId} for login.");

                return RedirectToAction(
                    "SignIn", "Saml2", new { idp = HttpUtility.UrlEncode(idpEntityId), returnUrl = returnUrl });
            }

            _logger.Log(LogLevel.Debug, $"SAML: AccountController.Login: Log in user {model.Email} locally.");

            // Authenticate locally
            var succeeded = _authenticationService.Authenticate(AuthenticationType.Local, model.Email, model.Password);

            if (succeeded)
            {
                return RedirectToLocal(returnUrl);
            }

            ModelState.AddModelError("", "Invalid login attempt.");

            return View(model);
        }

        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            var authenticationType = ((ClaimsIdentity)User.Identity).FindFirstValue(nameof(AuthenticationType));

            if (authenticationType == AuthenticationType.Saml.ToString())
            {
                return RedirectToAction("Logout", "Saml2");
            }

            _logger.Log(LogLevel.Debug, $"SAML: AccountController.Logout: Log out user {User.Identity.Name} locally.");

            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            return RedirectToAction("Index", "Home");
        }

        private SamlIdentityProvidersRepository SamlIdentityProvidersRepository
        {
            get => SamlIdentityProvidersRepository.GetInstance();
        }
    }
}