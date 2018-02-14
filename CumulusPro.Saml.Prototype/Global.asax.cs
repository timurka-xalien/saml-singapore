using CumulusPro.Saml.Prototype.Services;
using Sustainsys.Saml2.Mvc;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace CumulusPro.Saml.Prototype
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            // Wire up sustainsys logging
            Saml2Controller.Options.SPOptions.Logger = new SustainsysLoggerAdapter();
        }
    }
}