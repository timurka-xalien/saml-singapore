using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CumulusPro.Saml.Prototype.Startup))]
namespace CumulusPro.Saml.Prototype
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
