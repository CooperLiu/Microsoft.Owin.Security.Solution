using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(ExternalLoginWebSite.Startup))]
namespace ExternalLoginWebSite
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
