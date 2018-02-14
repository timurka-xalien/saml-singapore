using System.Net.Mail;

namespace CumulusPro.Saml.Prototype.Services.Services
{
    public static class Utils
    {
        public static string GetEmailDomain(string email)
        {
            MailAddress address = new MailAddress(email);
            return address.Host;
        }
    }
}