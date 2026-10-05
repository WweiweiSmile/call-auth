package services

import (
	"errors"
	"strings"
	"testing"

	"call-auth/config"
	"call-auth/dto"
	"call-auth/models"
)

func newAuthService(t *testing.T) *AuthService {
	t.Helper()
	return NewAuthService(setupTest(t))
}

func TestRegisterCreatesUserAndSignsIn(t *testing.T) {
	auth := newAuthService(t)

	resp, err := auth.Register(&dto.RegisterRequest{
		Username: "weiweigod", Password: "password123", Nickname: "维维",
	})
	if err != nil {
		t.Fatalf("注册应成功: %v", err)
	}

	// 注册完直接给登录态，用户不用再登一次
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatal("注册应同时返回登录态")
	}
	if resp.User.Role != models.UserRoleUser {
		t.Errorf("新用户角色应为 user，实际 %q —— 不能有隐式提权", resp.User.Role)
	}
	if resp.User.Nickname != "维维" {
		t.Errorf("昵称没存上: %q", resp.User.Nickname)
	}

	// 密码必须加密存储
	var stored models.User
	if err := config.DB.Where("username = ?", "weiweigod").First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Password == "password123" {
		t.Fatal("密码不能明文入库")
	}
	if !stored.CheckPassword("password123") {
		t.Error("存的 hash 应能校验原密码")
	}
}

func TestRegisterRejectsDuplicateUsername(t *testing.T) {
	auth := newAuthService(t)
	req := &dto.RegisterRequest{Username: "alice", Password: "password123"}

	if _, err := auth.Register(req); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Register(req); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("重复用户名应报 ErrUsernameTaken，实际 %v", err)
	}
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	auth := newAuthService(t)

	_, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: "short"})
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("短密码应被拒绝，实际 %v", err)
	}
	// 错误信息要说清具体原因，不能只说"密码不符合要求"
	if !strings.Contains(err.Error(), "至少") {
		t.Errorf("错误信息应说明具体原因，实际: %v", err)
	}
}

func TestRegisterRejectsPasswordBeyondBcryptLimit(t *testing.T) {
	auth := newAuthService(t)

	// bcrypt 只看前 72 字节，更长的部分**被静默丢弃**。
	// 也就是说两个前 72 字节相同的长密码会互相通过 —— 必须拒掉，
	// 而不是让用户以为自己设了个更安全的长密码
	tooLong := strings.Repeat("a", dto.MaxPasswordBytes+1)
	_, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: tooLong})
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("超过 bcrypt 上限的密码应被拒绝，实际 %v", err)
	}
}

func TestRegisterCountsPasswordByBytesNotRunes(t *testing.T) {
	auth := newAuthService(t)

	// 25 个汉字 = 75 字节 > 72。按字符算"才 25 个"会漏放，
	// 而 bcrypt 是按字节截断的
	_, err := auth.Register(&dto.RegisterRequest{
		Username: "alice",
		Password: strings.Repeat("密", 25),
	})
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("应按字节判断长度，实际 %v", err)
	}
}

func TestLoginSucceedsWithCorrectPassword(t *testing.T) {
	auth := newAuthService(t)
	if _, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: "password123"}); err != nil {
		t.Fatal(err)
	}

	resp, err := auth.Login(&dto.LoginRequest{Username: "alice", Password: "password123", ClientID: "call-front"})
	if err != nil {
		t.Fatalf("登录应成功: %v", err)
	}
	if resp.User.Username != "alice" {
		t.Errorf("返回的用户不对: %+v", resp.User)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	auth := newAuthService(t)
	if _, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: "password123"}); err != nil {
		t.Fatal(err)
	}

	_, err := auth.Login(&dto.LoginRequest{Username: "alice", Password: "wrong-password"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("密码错应报 ErrInvalidCredentials，实际 %v", err)
	}
}

func TestLoginUnknownUserLooksIdenticalToWrongPassword(t *testing.T) {
	auth := newAuthService(t)

	_, unknownErr := auth.Login(&dto.LoginRequest{Username: "nobody", Password: "password123"})
	if !errors.Is(unknownErr, ErrInvalidCredentials) {
		t.Fatalf("不存在的用户应报 ErrInvalidCredentials，实际 %v", unknownErr)
	}

	// 两条路径的**错误文案必须一模一样**：说得不一样等于给攻击者一个
	// 用户名枚举接口 —— 他靠文案差异就能筛出哪些用户名真实存在
	if _, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	_, wrongErr := auth.Login(&dto.LoginRequest{Username: "alice", Password: "nope-nope"})
	if unknownErr.Error() != wrongErr.Error() {
		t.Errorf("两种失败的文案必须一致，否则能被用来枚举用户名：%q vs %q",
			unknownErr.Error(), wrongErr.Error())
	}
}

func TestLoginRejectsDisabledAccount(t *testing.T) {
	auth := newAuthService(t)
	if _, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	if err := config.DB.Model(&models.User{}).Where("username = ?", "alice").
		Update("status", "inactive").Error; err != nil {
		t.Fatal(err)
	}

	// 密码正确但账号被禁：这时才明确说"被禁用"是安全的 ——
	// 对方已经知道正确密码了，不存在枚举问题
	_, err := auth.Login(&dto.LoginRequest{Username: "alice", Password: "password123"})
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("禁用账号应报 ErrAccountDisabled，实际 %v", err)
	}
}

func TestGetUser(t *testing.T) {
	auth := newAuthService(t)
	resp, err := auth.Register(&dto.RegisterRequest{Username: "alice", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}

	info, err := auth.GetUser(resp.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Username != "alice" {
		t.Errorf("取到的用户不对: %+v", info)
	}

	if _, err := auth.GetUser(999999); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("用户不存在时应报错，实际 %v", err)
	}
}
