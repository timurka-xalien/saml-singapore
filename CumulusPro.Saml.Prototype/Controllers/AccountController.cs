using CumulusPro.Saml.Prototype.Models;
using CumulusPro.Saml.Prototype.Services;
using CumulusPro.Saml.Prototype.Services.Services;
using Microsoft.AspNet.Identity;
using NLog;
using System.IdentityModel.Services;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace CumulusPro.Saml.Prototype.Controllers
{
    [Authorize]
    public partial class AccountController : Controller
    {
        private Logger _logger = LogManager.GetCurrentClassLogger();
        private ClaimsService _claimsService;
        private SamlIdentityProvidersRepository _identityProvidersRepository;
        private UserManagementService _userManagementService;

        public AccountController()
        {
            _userManagementService = new UserManagementService(AuthenticationManager, UserManager);
            _claimsService = new ClaimsService();
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
            ViewBag.IdentityProviders = _identityProvidersRepository.GetRegisteredIdentityProviders();
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
                _identityProvidersRepository.IsSamlAuthenticationRequired(emailDomain);

            if (isSamlAuthenticationRequired)
            {
                _logger.Log(LogLevel.Debug, $"SAML: AccountController.Login: Log in user {model.Email} via SAML SSO.");

                // Get appropriate IdP entity id
                var idpEntityId = _identityProvidersRepository.GetIdentityProviderEntityIdByEmailDomain(emailDomain);

                if (idpEntityId == null)
                {
                    _logger.Log(LogLevel.Warn, $"SAML: SamlController.SingleSignOn: IdP for domain {emailDomain} not found.");

                    return View("Error");
                }

                _logger.Log(LogLevel.Debug, $"SAML: AccountController.Login: Redirecting user to {idpEntityId} for login.");

                return RedirectToAction(
                    "SignIn", "Saml2", new { idp = idpEntityId, ReturnUrl = returnUrl });
            }

            _logger.Log(LogLevel.Debug, $"SAML: AccountController.Login: Log in user {model.Email} locally.");

            // Authenticate locally
            var succeeded = _userManagementService.AuthenticateLocally(model.Email, model.Password);

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
            _logger.Log(LogLevel.Debug, $"SAML: AccountController.LogOff: Log out user {User.Identity.Name}.");

            // Find out how user was signed in to understand how to sign him out
            var authenticationType = ((ClaimsIdentity)User.Identity).FindFirstValue(nameof(AuthenticationType));

            if (authenticationType == AuthenticationType.Saml.ToString())
            {
                // Get IdentityProvider settings
                var idpEntityId = _claimsService.GetIdentityProviderEntityId(User);
                var identityProvider = _identityProvidersRepository.GetIdentityProviderByEntityId(idpEntityId);

                // Initiate SLO only if IdentityProvider allows user to logout manually.
                // E.g., Okta, silently logs user out
                // For such providers we kill local session and redirect user to URL specified in RedirectOnLogoutUrl
                if (!identityProvider.SilentLogout)
                {
                    return RedirectToAction("Logout", "Saml2");
                }

                DeleteLocalSession();

                return Redirect(identityProvider.RedirectOnLogoutUrl);
            }

            DeleteLocalSession();

            return RedirectToAction("Index", "Home");
        }

        private void DeleteLocalSession()
        {
            _logger.Log(LogLevel.Debug, $"SAML: AccountController.DeleteLocalSession: Log out user {User.Identity.Name} locally.");

            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();
        }
    }
}