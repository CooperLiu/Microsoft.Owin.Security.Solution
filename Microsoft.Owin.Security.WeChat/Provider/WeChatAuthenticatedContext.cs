using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.WeChat
{
    public class WeChatAuthenticatedContext : BaseContext
    {
        public WeChatAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, int expires)
            :base(context)
        {

            User = user;

            AccessToken = accessToken;
            RefreshToken = refreshToken;
            ExpiresIn = TimeSpan.FromSeconds(expires);

            OpenId = TryGetValue<string>(user, "openid");
            Name = TryGetValue<string>(user, "nickname");
            Gender = TryGetValue<int>(user, "sex");
            Province = TryGetValue<string>(user, "province");
            City = TryGetValue<string>(user, "city");
            Country = TryGetValue<string>(user, "country");
            Language = TryGetValue<string>(user, "language");
            AvatarUrl = TryGetValue<string>(user, "headimgurl");
            Privilege = ((JArray)user["privilege"]).ToObject<IEnumerable<string>>();
            UnionId = TryGetValue<string>(user, "unionid");
            Id = UnionId ?? OpenId;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the WeChat access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the WeChat refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the WeChat access token expiration time
        /// </summary>
        public TimeSpan ExpiresIn { get; private set; }

        /// <summary>
        /// 当公众帐号绑定到开放平台时，NameIdentifier == UnionId, 否则 NameIdentifier == OpenId
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// 用户的唯一标识
        /// </summary>
        public string OpenId { get; private set; }

        /// <summary>
        /// 用户昵称
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// 用户的性别，值为1时是男性，值为2时是女性，值为0时是未知
        /// </summary>
        public int Gender { get; private set; }

        /// <summary>
        /// 用户个人资料填写的省份
        /// </summary>
        public string Province { get; private set; }

        /// <summary>
        /// 普通用户个人资料填写的城市
        /// </summary>
        public string City { get; private set; }

        /// <summary>
        /// 国家，如中国为CN
        /// </summary>
        public string Country { get; private set; }

        /// <summary>
        /// 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
        /// </summary>
        public string Language { get; private set; }

        /// <summary>
        /// 用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空。若用户更换头像，原有头像URL将失效。
        /// </summary>
        public string AvatarUrl { get; private set; }

        /// <summary>
        /// 用户特权信息，json 数组，如微信沃卡用户为（chinaunicom）
        /// </summary>
        public IEnumerable<string> Privilege { get; private set; }

        /// <summary>
        /// 只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段。
        /// </summary>
        public string UnionId { get; private set; }


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
