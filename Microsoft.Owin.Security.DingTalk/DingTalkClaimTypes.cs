namespace Microsoft.Owin.Security.DingTalk
{
    public class DingTalkClaimTypes
    {
        public const string OpenId = "urn:wechat:openid";
        public const string UnionId = "urn:wechat:unionid";
        public const string AccessToken = "urn:wechat:accesstoken";
        public const string PersistentCode = "urn:wechat:refreshtoken";
        public const string AccessTokenExpiresUtc = "urn:wechat:accesstokenexpiresutc";
    }
}