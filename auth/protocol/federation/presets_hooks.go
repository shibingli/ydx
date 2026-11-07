package federation

import (
	"context"
	"net/http"

	"github.com/shibingli/ydx/errs"
)

// facebookUserInfo maps Facebook Graph user data, including the nested picture URL.
// facebookUserInfo 映射 Facebook Graph 用户数据，包括嵌套的头像 URL。
func facebookUserInfo(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error) {
	status, body, err := getProvider(ctx, client, p.UserInfoURL, map[string]string{
		"Authorization": "Bearer " + token.AccessToken,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrUserInfo)
	}
	if status != http.StatusOK {
		return nil, providerStatusError(ErrUserInfo, p.Name, "UserInfo", status)
	}
	raw, err := parseJSONObject(body)
	if err != nil {
		return nil, errs.Detail(ErrUserInfo, "facebook UserInfo is invalid | Facebook UserInfo 非法")
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrUserInfo, "facebook UserInfo returned %s | Facebook UserInfo 返回 %s", code, code)
	}
	identity := identityFromMap(p.Name, raw)
	identity.EmailVerified = false
	identity.Username = ""
	if picture := nestedMap(raw, "picture"); picture != nil {
		if data := nestedMap(picture, "data"); data != nil {
			identity.AvatarURL = firstNonEmpty(stringValue(data["url"]), identity.AvatarURL)
		}
	}
	if identity.Subject == "" {
		return nil, errs.Detail(ErrUserInfo, "facebook UserInfo has no id | Facebook UserInfo 缺少 id")
	}
	return identity, nil
}
