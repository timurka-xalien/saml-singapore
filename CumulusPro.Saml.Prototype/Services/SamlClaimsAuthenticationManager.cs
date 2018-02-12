using Microsoft.AspNet.Identity.Owin;
using System.Security.Claims;
using System.Web;

namespace CumulusPro.Saml.Prototype.Services
{
    /// <summary>
    /// Use this class to map attributes from different Identity Providers to the single format.
    /// We do not have here any info about which IdP exactly user was authenticated by so we need
    /// to guess by analyzing some user attributes
    /// </summary>
    public class SamlClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        private AuthenticationService _authenticationService;
        private ClaimsService _claimsService;

        public SamlClaimsAuthenticationManager()
        {
            _claimsService = new ClaimsService();
            // Cannot create AuthenticationService here as this ctor is called at a very early stage when HttpContext is not avaialable
        }

        public AuthenticationService AuthenticationService
        {
            get
            {
                if (_authenticationService == null)
                {
                    _authenticationService = _authenticationService = new AuthenticationService(
                        HttpContext.Current?.GetOwinContext()?.Authentication,
                        HttpContext.Current?.GetOwinContext()?.GetUserManager<ApplicationUserManager>());
                }

                return _authenticationService;
            }
        }

        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            _claimsService.SetPrincipalAdditionalClaims(incomingPrincipal);
            RegisterUserIfNeeded(incomingPrincipal);

            return incomingPrincipal;
        }

        private void RegisterUserIfNeeded(ClaimsPrincipal incomingPrincipal)
        {
            // Call your user registration logic here
            AuthenticationService.RegisterNewUserIfNeeded(incomingPrincipal);
        }
    }
}