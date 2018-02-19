using System.Net.Mail;
using System.Web;
using System.Web.Mvc;

namespace CumulusPro.Saml.Prototype.Services.Services
{
    public static class Utils
    {
        public static string GetEmailDomain(string email)
        {
            MailAddress address = new MailAddress(email);
            return address.Host;
        }

        public static string GetContentFolderImageUrl(string imageFileName)
        {
            return new UrlHelper(HttpContext.Current.Request.RequestContext).Content("~/Content/Images/" + imageFileName);
        }
    }
}