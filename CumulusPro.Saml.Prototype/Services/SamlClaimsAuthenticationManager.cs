using Microsoft.AspNet.Identity.Owin;
using System.Security.Claims;
using System.Web;

namespace CumulusPro.Saml.Prototype.Services
{
    /// <summary>
    /// This class' Authenticate() method is called after Systainsys has finished authenticating user.
    /// So here you can perform any additional actions 
    /// We use this class to call ClaimsService which will map attributes from different Identity Providers to the single format.
    /// </summary>
    public class SamlClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        private ClaimsService _claimsService;

        public SamlClaimsAuthenticationManager()
        {
            _claimsService = new ClaimsService();
            // Cannot create UserManagementService here as this ctor is called at a very early stage when HttpContext is not avaialable
        }

        public UserManagementService UserManagementService
        {
            get
            {
                 return new UserManagementService(
                    HttpContext.Current.GetOwinContext().Authentication,
                    HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>());
            }
        }

        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            _claimsService.AddPrincipalExtraClaims(incomingPrincipal);
            RegisterUserIfNeeded(incomingPrincipal);

            return incomingPrincipal;
        }

        private void RegisterUserIfNeeded(ClaimsPrincipal incomingPrincipal)
        {
            // Call your user registration logic here
            UserManagementService.RegisterNewUserIfNeeded(incomingPrincipal);
        }
    }
}