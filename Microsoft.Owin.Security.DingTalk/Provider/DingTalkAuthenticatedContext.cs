using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.DingTalk
{
    public class DingTalkAuthenticatedContext : BaseContext
    {
        public DingTalkAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string persistentCode, int expires)
            : base(context)
        {

            User = user;

            AccessToken = accessToken;
            PersistentCode = persistentCode;
            SnsTokenExpiresIn = TimeSpan.FromSeconds(expires);

            OpenId = user["user_info"].Value<string>("openid"); 
            Nick = user["user_info"].Value<string>("nick");
            UnionId = user["user_info"].Value<string>("unionid");
            DingId = user["user_info"].Value<string>("dingId");
            Id = UnionId ?? OpenId;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the DingTalk access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// 用户给开放应用授权的持久授权码，此码目前无过期时间
        /// </summary>
        public string PersistentCode { get; private set; }

        /// <summary>
        /// Gets the DingTalk access token expiration time
        /// </summary>
        public TimeSpan SnsTokenExpiresIn { get; private set; }

        /// <summary>
        /// 当公众帐号绑定到开放平台时，NameIdentifier == UnionId, 否则 NameIdentifier == OpenId
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// 用户在当前开放应用内的唯一标识
        /// </summary>
        public string OpenId { get; private set; }

        /// <summary>
        /// 用户在当前开放应用所属的钉钉开放平台账号内的唯一标识
        /// </summary>
        public string UnionId { get; private set; }

        /// <summary>
        /// 钉钉Id
        /// </summary>
        public string DingId { get; set; }

        /// <summary>
        /// 用户昵称
        /// </summary>
        public string Nick { get; private set; }

        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static T TryGetValue<T>(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.Value<T>() : default(T);
        }
    }
}
