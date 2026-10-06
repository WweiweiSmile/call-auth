package services

import (
	"errors"
	"strings"
	"testing"
	"time"

	"call-auth/config"
	"call-auth/models"
	"call-auth/utils"
)

// seedClient 往注册表里塞一个 client。
//
// 测试刻意不依赖 models.DefaultSSOClients：那是生产种子数据，改它不该让
// 这些断言跟着变。用自己造的数据，测的是 ResolveClient 的逻辑本身
func seedClient(t *testing.T, clientID string, isActive bool, redirectURIs ...string) {
	t.Helper()

	raw := `["` + strings.Join(redirectURIs, `","`) + `"]`
	client := models.SSOClient{
		ClientID:     clientID,
		Name:         clientID,
		RedirectURIs: raw,
		IsActive:     isActive,
	}
	if err := config.DB.Create(&client).Error; err != nil {
		t.Fatal(err)
	}
	// 先建成启用的，再按需停用 —— 见 SSOClient.IsActive 上的说明：
	// Create 传 false 会被列默认值 true 顶掉
	if !isActive {
		if err := config.DB.Model(&models.SSOClient{}).
			Where("client_id = ?", clientID).
			Update("is_active", false).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveClient(t *testing.T) {
	tokens := setupTest(t)
	sso := NewSSOService(tokens)

	seedClient(t, "app", true, "https://a.qwnet.top/auth/callback", "https://app.qwnet.top/auth/callback")
	seedClient(t, "hash-app", true, "https://h.qwnet.top/#/pages/auth/callback")
	seedClient(t, "disabled", false, "https://d.qwnet.top/auth/callback")

	cases := []struct {
		name      string
		clientID  string
		requested string
		want      string
		wantErr   bool
	}{
		{"未登记的 client 一律拒", "nobody", "", "", true},
		{"已停用的 client 也拒", "disabled", "", "", true},
		{"client_id 为空拒", "", "", "", true},
		{"不传 redirect_uri 用登记的第一个", "app", "", "https://a.qwnet.top/auth/callback", false},
		{"精确匹配放行", "app", "https://app.qwnet.top/auth/callback", "https://app.qwnet.top/auth/callback", false},
		{"不在白名单的地址拒掉", "app", "https://evil.com/auth/callback", "", true},
		// 前缀相同、多一段后缀 —— 这正是"用 HasPrefix 实现"会漏掉的那个绕过
		{"前缀相同但域名更长不能放行", "app", "https://a.qwnet.top.evil.com/auth/callback", "", true},
		{"hash 形态的地址要能原样匹配", "hash-app", "https://h.qwnet.top/#/pages/auth/callback", "https://h.qwnet.top/#/pages/auth/callback", false},
		{"少了 #/pages 一段就拒", "hash-app", "https://h.qwnet.top/auth/callback", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sso.ResolveClient(tc.clientID, tc.requested)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidSSORequest) {
					t.Fatalf("想要 ErrInvalidSSORequest，得到 %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该出错: %v", err)
			}
			if got != tc.want {
				t.Fatalf("跳转目标 = %q，想要 %q", got, tc.want)
			}
		})
	}
}

func TestValidNext(t *testing.T) {
	ok := []string{
		"/sso?client_id=call-front&state=abc",
		"/sso?client_id=x",
	}
	bad := []string{
		"",
		"/login?next=/sso?x",
		"/sso",                       // 少了 ?，/sso 自己也会 400，没必要放行
		"/ssoX?client_id=x",          // 前缀不完整
		"//evil.com/sso?client_id=x", // 协议相对 URL，浏览器会当成 https://evil.com
		"https://evil.com/sso?x=1",
		"http://localhost:8020/sso?x=1",
		" /sso?x=1", // 前导空白
	}

	for _, next := range ok {
		if !ValidNext(next) {
			t.Errorf("%q 应该被放行", next)
		}
	}
	for _, next := range bad {
		if ValidNext(next) {
			t.Errorf("%q 不该被放行", next)
		}
	}
}

func TestResolveLogoutTarget(t *testing.T) {
	tokens := setupTest(t)
	sso := NewSSOService(tokens)

	seedClient(t, "call-front", true,
		"http://localhost:3000/#/pages/auth/callback",
		"https://call.qwnet.top/#/pages/auth/callback")
	seedClient(t, "learn-daily", true, "https://learn.qwnet.top/auth/callback")

	cases := []struct {
		name    string
		next    string
		want    string
		wantErr bool
	}{
		{"本机 origin 放行", "http://localhost:3000", "http://localhost:3000", false},
		{"线上 origin 放行", "https://call.qwnet.top", "https://call.qwnet.top", false},
		{"带尾部斜杠也放行", "https://call.qwnet.top/", "https://call.qwnet.top", false},
		{"另一个 client 的 origin 也放行", "https://learn.qwnet.top", "https://learn.qwnet.top", false},
		{"没注册过的域拒掉", "https://evil.com", "", true},
		{"空值拒掉", "", "", true},
		{"相对路径拒掉", "/logout", "", true},
		// 关键：一旦允许带路径，next 就退化成任意跳转
		{"带路径拒掉", "https://call.qwnet.top/evil", "", true},
		{"同域不同端口拒掉", "https://call.qwnet.top:8443", "", true},
		{"别的 scheme 拒掉", "ftp://call.qwnet.top", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sso.ResolveLogoutTarget(tc.next)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidSSORequest) {
					t.Fatalf("想要 ErrInvalidSSORequest，得到 %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该出错: %v", err)
			}
			if got != tc.want {
				t.Fatalf("跳转目标 = %q，想要 %q", got, tc.want)
			}
		})
	}
}

func TestCallbackURL(t *testing.T) {
	cases := []struct {
		name     string
		redirect string
		ticket   string
		state    string
		want     string
	}{
		{
			// hash 模式：参数必须拼在 # 之后，成为 fragment 的一部分。
			// 用 url.Parse 改 RawQuery 会把这整段丢掉
			name: "hash 模式的地址", redirect: "https://call.qwnet.top/#/pages/auth/callback",
			ticket: "tk", state: "st",
			want: "https://call.qwnet.top/#/pages/auth/callback?ticket=tk&state=st",
		},
		{
			name: "非 hash 的地址", redirect: "https://learn.qwnet.top/auth/callback",
			ticket: "tk", state: "st",
			want: "https://learn.qwnet.top/auth/callback?ticket=tk&state=st",
		},
		{
			name: "没有 state 时不带这个参数", redirect: "https://learn.qwnet.top/auth/callback",
			ticket: "tk", state: "",
			want: "https://learn.qwnet.top/auth/callback?ticket=tk",
		},
		{
			name: "地址本身带 query 时改用 &", redirect: "https://learn.qwnet.top/auth/callback?a=1",
			ticket: "tk", state: "",
			want: "https://learn.qwnet.top/auth/callback?a=1&ticket=tk",
		},
		{
			name: "state 里的特殊字符要转义", redirect: "https://learn.qwnet.top/auth/callback",
			ticket: "tk", state: "a b&c",
			want: "https://learn.qwnet.top/auth/callback?ticket=tk&state=a+b%26c",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CallbackURL(tc.redirect, tc.ticket, tc.state); got != tc.want {
				t.Fatalf("得到 %q，想要 %q", got, tc.want)
			}
		})
	}
}

func TestIssueSSOSessionHasSSOScope(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "sso_scope_user")

	plain, err := tokens.IssueSSOSession(user)
	if err != nil {
		t.Fatal(err)
	}
	if plain == "" {
		t.Fatal("会话明文不该为空")
	}

	var row models.RefreshToken
	if err := config.DB.Where("token_hash = ?", utils.HashToken(plain)).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Scope != models.ScopeSSO {
		t.Fatalf("scope = %q，想要 %q", row.Scope, models.ScopeSSO)
	}
	// 会话有效期应该明显长于应用登录态（30 天 vs 14 天）——
	// 这是"一段时间不用重复登录"的来源，缩短它等于悄悄改了产品行为
	if !row.ExpiresAt.After(time.Now().Add(20 * 24 * time.Hour)) {
		t.Fatalf("会话过期时间太短: %v", row.ExpiresAt)
	}
}

// TestRefreshRejectsSSOSession 盯的是本项目里最容易踩的那个坑：
//
// SSO 会话被 /auth/refresh 轮换掉之后，cookie 里那份就成了"已用过的旧 token"，
// 之后**每一次** /sso 都会撞上重放检测，把用户全部登录态吊销。
// 现象是"莫名其妙被登出所有设备"，而根因在另一个接口里，极难定位
func TestRefreshRejectsSSOSession(t *testing.T) {
	tokens := setupTest(t)
	sso := NewSSOService(tokens)
	user := createUser(t, "sso_refresh_user")

	session, err := tokens.IssueSSOSession(user)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tokens.Refresh(session); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("用 SSO 会话换 access token 应该被拒，得到 %v", err)
	}

	// 被拒之后它**不能被消费掉**
	var row models.RefreshToken
	if err := config.DB.Where("token_hash = ?", utils.HashToken(session)).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.UsedAt != nil {
		t.Fatal("SSO 会话被 /auth/refresh 消费掉了 —— 之后的 /sso 会全部撞上重放检测")
	}

	// 而且它仍然可用
	if _, err := sso.SessionUser(session); err != nil {
		t.Fatalf("会话应该还能用: %v", err)
	}
}

func TestSessionUserRejectsAppToken(t *testing.T) {
	tokens := setupTest(t)
	sso := NewSSOService(tokens)
	user := createUser(t, "sso_apptoken_user")

	// 应用登录态不能冒充 SSO 会话：两者的 scope 不同，
	// 而且应用 token 是会被应用自己拿着到处发的
	resp, err := tokens.Issue(user, "call-front")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sso.SessionUser(resp.RefreshToken); !errors.Is(err, ErrSSOSessionInvalid) {
		t.Fatalf("应用登录态不该被当成 SSO 会话，得到 %v", err)
	}
}

func TestSessionUserRejectsDeadSessions(t *testing.T) {
	tokens := setupTest(t)
	sso := NewSSOService(tokens)
	user := createUser(t, "sso_dead_user")

	t.Run("空值", func(t *testing.T) {
		if _, err := sso.SessionUser(""); !errors.Is(err, ErrSSOSessionInvalid) {
			t.Fatalf("得到 %v", err)
		}
	})

	t.Run("不存在的会话", func(t *testing.T) {
		if _, err := sso.SessionUser("deadbeef"); !errors.Is(err, ErrSSOSessionInvalid) {
			t.Fatalf("得到 %v", err)
		}
	})

	t.Run("已吊销的会话", func(t *testing.T) {
		session, err := tokens.IssueSSOSession(user)
		if err != nil {
			t.Fatal(err)
		}
		if err := tokens.Logout(user.ID, session); err != nil {
			t.Fatal(err)
		}
		if _, err := sso.SessionUser(session); !errors.Is(err, ErrSSOSessionInvalid) {
			t.Fatalf("已吊销的会话不该还能用，得到 %v", err)
		}
	})

	t.Run("已过期的会话", func(t *testing.T) {
		session, err := tokens.IssueSSOSession(user)
		if err != nil {
			t.Fatal(err)
		}
		expireRefreshToken(t, session)
		if _, err := sso.SessionUser(session); !errors.Is(err, ErrSSOSessionInvalid) {
			t.Fatalf("已过期的会话不该还能用，得到 %v", err)
		}
	})

	t.Run("账号被禁用时连会话一起清掉", func(t *testing.T) {
		other := createUser(t, "sso_disabled_user")
		session, err := tokens.IssueSSOSession(other)
		if err != nil {
			t.Fatal(err)
		}
		if err := config.DB.Model(&models.User{}).Where("id = ?", other.ID).
			Update("status", "inactive").Error; err != nil {
			t.Fatal(err)
		}

		if _, err := sso.SessionUser(session); !errors.Is(err, ErrSSOSessionInvalid) {
			t.Fatalf("被禁用账号的会话不该还能用，得到 %v", err)
		}

		// 而且这条会话应该已经被吊销了，不然它会一直活到 30 天后
		var row models.RefreshToken
		if err := config.DB.Where("token_hash = ?", utils.HashToken(session)).First(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.RevokedAt == nil {
			t.Fatal("被禁用账号的会话没有被清掉")
		}
	})
}

func TestTicketLifecycle(t *testing.T) {
	tokens := setupTest(t)
	sso := NewSSOService(tokens)
	user := createUser(t, "ticket_user")
	seedClient(t, "app", true, "https://app.qwnet.top/auth/callback")
	seedClient(t, "other", true, "https://other.qwnet.top/auth/callback")

	const callback = "https://app.qwnet.top/auth/callback"

	t.Run("签发后能兑换一次", func(t *testing.T) {
		ticket, err := sso.IssueTicket(user.ID, "app", callback)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sso.ConsumeTicket(ticket, "app")
		if err != nil {
			t.Fatalf("兑换失败: %v", err)
		}
		if got.ID != user.ID {
			t.Fatalf("兑换出的用户 = %d，想要 %d", got.ID, user.ID)
		}

		// 一张票只能用一次
		if _, err := sso.ConsumeTicket(ticket, "app"); !errors.Is(err, ErrInvalidTicket) {
			t.Fatalf("同一张票不该能兑第二次，得到 %v", err)
		}
	})

	t.Run("client_id 对不上就拒", func(t *testing.T) {
		ticket, err := sso.IssueTicket(user.ID, "app", callback)
		if err != nil {
			t.Fatal(err)
		}
		// A 应用拿着 B 应用的票来换 —— 必须拒
		if _, err := sso.ConsumeTicket(ticket, "other"); !errors.Is(err, ErrInvalidTicket) {
			t.Fatalf("跨 client 兑换不该成功，得到 %v", err)
		}
		// 而且不能因为它被拒就把票作废了，原主还得能兑
		if _, err := sso.ConsumeTicket(ticket, "app"); err != nil {
			t.Fatalf("原 client 应该还能兑换: %v", err)
		}
	})

	t.Run("过期的票拒掉", func(t *testing.T) {
		ticket, err := sso.IssueTicket(user.ID, "app", callback)
		if err != nil {
			t.Fatal(err)
		}
		expireTicket(t, ticket)
		if _, err := sso.ConsumeTicket(ticket, "app"); !errors.Is(err, ErrInvalidTicket) {
			t.Fatalf("过期的票不该能兑，得到 %v", err)
		}
	})

	t.Run("不存在的票拒掉", func(t *testing.T) {
		if _, err := sso.ConsumeTicket("deadbeef", "app"); !errors.Is(err, ErrInvalidTicket) {
			t.Fatalf("得到 %v", err)
		}
	})

	t.Run("缺参数拒掉", func(t *testing.T) {
		if _, err := sso.ConsumeTicket("", "app"); !errors.Is(err, ErrInvalidTicket) {
			t.Fatalf("得到 %v", err)
		}
		if _, err := sso.ConsumeTicket("x", ""); !errors.Is(err, ErrInvalidTicket) {
			t.Fatalf("得到 %v", err)
		}
	})
}

// TestLogoutKeepsSSOSession 是 §6.4 那条规则的守门测试：
// 在 A 应用登出不能把 B 应用一起踢掉
func TestLogoutKeepsSSOSession(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "logout_scope_user")

	app, err := tokens.Issue(user, "call-front")
	if err != nil {
		t.Fatal(err)
	}
	session, err := tokens.IssueSSOSession(user)
	if err != nil {
		t.Fatal(err)
	}

	// 应用侧"登出所有设备"
	if err := tokens.Logout(user.ID, ""); err != nil {
		t.Fatal(err)
	}

	if revokedAt(t, app.RefreshToken) == nil {
		t.Fatal("应用登录态应该被吊销")
	}
	if revokedAt(t, session) != nil {
		t.Fatal("登出把 SSO 会话也吊销了 —— A 应用登出会把 B 应用一起踢掉")
	}
}

// TestRevokeAllKillsEverything 是上面那条的对照组：
// 安全事件（重放、账号被禁用）要连会话一起清
func TestRevokeAllKillsEverything(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "revoke_all_user")

	app, err := tokens.Issue(user, "call-front")
	if err != nil {
		t.Fatal(err)
	}
	session, err := tokens.IssueSSOSession(user)
	if err != nil {
		t.Fatal(err)
	}

	tokens.RevokeAll(user.ID)

	if revokedAt(t, app.RefreshToken) == nil {
		t.Fatal("RevokeAll 应该吊销应用登录态")
	}
	if revokedAt(t, session) == nil {
		t.Fatal("RevokeAll 应该连 SSO 会话一起吊销 —— 留下它，攻击者还能换出任意应用的 token")
	}
}

// revokedAt 取某个 token 的吊销时间，没吊销返回 nil
func revokedAt(t *testing.T, plain string) *time.Time {
	t.Helper()

	var row models.RefreshToken
	if err := config.DB.Where("token_hash = ?", utils.HashToken(plain)).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row.RevokedAt
}

// expireRefreshToken 把某条登录态的过期时间改到过去，模拟"它已经过期了"
func expireRefreshToken(t *testing.T, plain string) {
	t.Helper()

	if err := config.DB.Model(&models.RefreshToken{}).
		Where("token_hash = ?", utils.HashToken(plain)).
		Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
}

// expireTicket 把某张票据改到过期
func expireTicket(t *testing.T, plain string) {
	t.Helper()

	if err := config.DB.Model(&models.SSOTicket{}).
		Where("ticket_hash = ?", utils.HashToken(plain)).
		Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
}
