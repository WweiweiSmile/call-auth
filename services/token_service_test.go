package services

import (
	"errors"
	"testing"
	"time"

	"call-auth/config"
	"call-auth/models"
	"call-auth/utils"
)

func TestIssueStoresHashNotPlaintext(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	resp, err := tokens.Issue(user, "call-front")
	if err != nil {
		t.Fatal(err)
	}

	rows := refreshRows(t, user.ID)
	if len(rows) != 1 {
		t.Fatalf("应写入一条 refresh token，实际 %d", len(rows))
	}

	// 库里存的必须是 hash：数据库泄露时，攻击者拿到的 hash 不能直接用来登录
	if rows[0].TokenHash == resp.RefreshToken {
		t.Fatal("库里存的不能是明文")
	}
	if rows[0].TokenHash != utils.HashToken(resp.RefreshToken) {
		t.Fatal("存的应是明文的 sha256")
	}
	if rows[0].ClientID != "call-front" {
		t.Errorf("client_id 应记录来源，实际 %q", rows[0].ClientID)
	}
	if rows[0].UsedAt != nil || rows[0].RevokedAt != nil {
		t.Error("刚签发的 token 不该是已用或已吊销状态")
	}
}

func TestRefreshRotatesAndInvalidatesTheOldOne(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	first, _ := tokens.Issue(user, "call-front")

	second, err := tokens.Refresh(first.RefreshToken)
	if err != nil {
		t.Fatalf("首次轮换应成功: %v", err)
	}

	// 新的必须和旧的不一样 —— "轮换"的意思就是换了一个
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("轮换后应返回新的 refresh token")
	}

	rows := refreshRows(t, user.ID)
	if len(rows) != 2 {
		t.Fatalf("轮换应新增一行（旧行保留以便检测重放），实际 %d 行", len(rows))
	}

	var old models.RefreshToken
	if err := config.DB.Where("token_hash = ?", utils.HashToken(first.RefreshToken)).
		First(&old).Error; err != nil {
		t.Fatal(err)
	}
	if !old.WasRotated() {
		t.Error("旧的 refresh token 应被标记为已使用")
	}

	// 新签发的 access token 必须能用
	if _, err := tokens.Verify(second.AccessToken); err != nil {
		t.Errorf("轮换后拿到的 access token 应验签通过: %v", err)
	}
}

func TestRefreshReuseRevokesEverything(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	first, _ := tokens.Issue(user, "call-front")
	second, _ := tokens.Refresh(first.RefreshToken)

	// 再用一次**旧的** refresh token。
	// 这只有两种可能：客户端并发重试，或者 token 被偷了。分不清，
	// 所以一律按泄露处理
	_, err := tokens.Refresh(first.RefreshToken)
	if !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("重放应返回 ErrTokenReuse，实际 %v", err)
	}

	// 关键是**连新的也一起吊销** —— 泄露发生时不能假设攻击者手上是哪一个
	if _, err := tokens.Refresh(second.RefreshToken); err == nil {
		t.Fatal("检测到重放后，该用户全部登录态都应失效")
	}

	for _, row := range refreshRows(t, user.ID) {
		if row.RevokedAt == nil {
			t.Errorf("token %d 应被吊销", row.ID)
		}
	}
}

func TestLogoutDoesNotLookLikeReuse(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	pair, _ := tokens.Issue(user, "call-front")
	if err := tokens.Logout(user.ID, pair.RefreshToken); err != nil {
		t.Fatal(err)
	}

	// 登出之后再用这个 token，是"正常死亡"，不是重放。
	// 报 ErrTokenReuse 的话会连带吊销该用户其他设备的登录态 —— 那是误伤
	_, err := tokens.Refresh(pair.RefreshToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("登出后的 token 应报 ErrTokenInvalid，实际 %v", err)
	}
}

func TestLogoutOnlyKillsTheOneToken(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	phone, _ := tokens.Issue(user, "call-front")
	tablet, _ := tokens.Issue(user, "call-front")

	if err := tokens.Logout(user.ID, phone.RefreshToken); err != nil {
		t.Fatal(err)
	}

	if _, err := tokens.Refresh(phone.RefreshToken); err == nil {
		t.Error("登出的那个应该失效")
	}
	if _, err := tokens.Refresh(tablet.RefreshToken); err != nil {
		t.Errorf("另一台设备不该被连累: %v", err)
	}
}

func TestLogoutAllDevices(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	phone, _ := tokens.Issue(user, "call-front")
	tablet, _ := tokens.Issue(user, "call-back")

	tokens.RevokeAll(user.ID)

	for name, pair := range map[string]string{"手机": phone.RefreshToken, "平板": tablet.RefreshToken} {
		if _, err := tokens.Refresh(pair); err == nil {
			t.Errorf("%s 的登录态应被清除", name)
		}
	}
}

func TestRefreshRejectsExpired(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	pair, _ := tokens.Issue(user, "call-front")

	// 把过期时间改到过去。用直接改库的方式，避免为测试去调 TTL 配置
	past := time.Now().Add(-time.Minute)
	if err := config.DB.Model(&models.RefreshToken{}).
		Where("user_id = ?", user.ID).
		Update("expires_at", past).Error; err != nil {
		t.Fatal(err)
	}

	// 过期是"正常死亡"，必须报 ErrTokenInvalid 而不是 ErrTokenReuse ——
	// 否则每个用户放着不管两周后回来，都会被当成疑似盗号
	_, err := tokens.Refresh(pair.RefreshToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("过期应报 ErrTokenInvalid，实际 %v", err)
	}
}

func TestRefreshRejectedWhenAccountDisabled(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	pair, _ := tokens.Issue(user, "call-front")

	if err := config.DB.Model(&models.User{}).Where("id = ?", user.ID).
		Update("status", "inactive").Error; err != nil {
		t.Fatal(err)
	}

	if _, err := tokens.Refresh(pair.RefreshToken); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("账号被禁用时应拒绝续期，实际 %v", err)
	}

	// 顺带把残留的登录态清掉，否则这个 token 会一直活到过期
	for _, row := range refreshRows(t, user.ID) {
		if row.RevokedAt == nil {
			t.Error("账号被禁用后，其登录态应被清除")
		}
	}
}

func TestRefreshRejectsUnknownToken(t *testing.T) {
	tokens := setupTest(t)

	_, err := tokens.Refresh("deadbeef")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("不存在的 token 应报 ErrTokenInvalid，实际 %v", err)
	}
}

func TestIssuedTokenPassesOwnVerification(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	pair, _ := tokens.Issue(user, "call-front")

	claims, err := tokens.Verify(pair.AccessToken)
	if err != nil {
		t.Fatalf("自己签的 token 必须能通过自己的验签: %v", err)
	}
	id, err := claims.UserID()
	if err != nil || id != user.ID {
		t.Errorf("取出的用户 id 不对: %d (err=%v)", id, err)
	}
	if claims.Role != models.UserRoleUser {
		t.Errorf("role 应为 user，实际 %q", claims.Role)
	}
}

func TestPlaintextRefreshTokenNeverAppearsInDatabase(t *testing.T) {
	tokens := setupTest(t)
	user := createUser(t, "alice")

	pair, _ := tokens.Issue(user, "call-front")

	// 全表扫一遍，明文不能出现在任何字段里
	var rows []models.RefreshToken
	if err := config.DB.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.TokenHash == pair.RefreshToken {
			t.Fatal("明文出现在了数据库里")
		}
	}
}
