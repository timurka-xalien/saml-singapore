using Newtonsoft.Json;
using System.IO;
using System.Net.Mail;
using System.Runtime.Serialization.Formatters;
using System.Text;

namespace CumulusPro.Saml.Prototype.Services.Services
{
    public static class Utils
    {
        public static string GetEmailDomain(string email)
        {
            MailAddress address = new MailAddress(email);
            return address.Host;
        }

        public static string SerializeToJson<T>(T data)
        {
            return JsonConvert.SerializeObject(data, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.None,
                TypeNameAssemblyFormat = FormatterAssemblyStyle.Simple,
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
                Formatting = Formatting.Indented,
                DateTimeZoneHandling = DateTimeZoneHandling.Utc,
                Error = (sender, args) => args.ErrorContext.Handled = true,
            });
        }

        public static T DeserializeFromJson<T>(string data)
        {
            return JsonConvert.DeserializeObject<T>(data);
        }
    }
}