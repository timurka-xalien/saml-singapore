using CumulusPro.Saml.Prototype.Models;
using CumulusPro.Saml.Prototype.Services;
using CumulusPro.Saml.Prototype.Services.Services;
using Microsoft.AspNet.Identity;
using NLog;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
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
            _identityProvidersRepository = new SamlIdentityProvidersRepository();
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
            // This is just quick and dirty solution. Use dedicated model instead
            ViewBag.IdentityProviders = _identityProvidersRepository.GetRegisteredIdentityProviders();
            return View();
        }

        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check if we need to login user locally (in case no SAML Identity Provider is registered for specified email domain)
            var emailDomain = Utils.GetEmailDomain(model.Email);
            var isSamlAuthenticationRequired = IsSamlAuthenticationRequired(emailDomain);

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

        [AllowAnonymous]
        public ActionResult OnOneLoginLogout()
        {
            // Despite the fact that we do not implement SLO with OneLogin they do redirect user 
            // to the prototype after user logs out from OneLogin site. 
            // Moreover with the redirect they send non-signed logout message 
            // which is a violation of SAML specification. 
            // And as far as Sustainsys demands that all messages are signed, it throws an exception. 
            // It turned out that this is a known issue described here: 
            //    https://github.com/Sustainsys/Saml2/issues/503. 
            // Sustainsys suggested to fix it as a sponsored development. 
            // So I added a workaround for this issue here as I think that it is better not to alter
            // Sustainsys library in cases when we can deal with an issue on our side
            // Feel free to remove this workaround and make a fix in Sustainsys library code.

            // We cannot let OneLogin to redirect to Sustainsys Saml2Controller on logout so
            // we configure OneLogin to redirect to this action and here we just redirect user back to OneLogin,
            // to URL which forcibly logs out user
            var oneLoginIdP = _identityProvidersRepository.FindIdentityProviderBySearchTerm("OneLogin");
            return Redirect(oneLoginIdP.ForcedLogoutUrl);
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

        /// <summary>
        /// Check if user having email at specified emailDomain have to be authenticated using SAML SSO
        /// </summary>
        private bool IsSamlAuthenticationRequired(string emailDomain)
        {
            return _identityProvidersRepository.GetRegisteredEmailDomains().Contains(emailDomain);
        }
    }
}