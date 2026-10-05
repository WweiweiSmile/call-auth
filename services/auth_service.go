package services

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"call-auth/config"
	"call-auth/dto"
	"call-auth/models"
)

const (
	minUsernameLen = 3
	minPasswordLen = 8
)

type AuthService struct {
	tokens *TokenService
}

func NewAuthService(tokens *TokenService) *AuthService {
	return &AuthService{tokens: tokens}
}

// ToUserInfo 模型转对外结构
func ToUserInfo(user *models.User) dto.UserInfo {
	return dto.UserInfo{
		ID:       user.ID,
		Username: user.Username,
		Nickname: user.Nickname,
		Avatar:   user.Avatar,
		Role:     user.Role,
	}
}

// dummyHash 一个固定的合法 bcrypt hash，用于「用户名不存在时也跑一次比对」。
//
// 见 Login 里的说明：不跑的话响应时间会泄露"这个用户名存不存在"。
// 在包初始化时算出来，而不是写死一个字符串 —— 写死的 hash 如果 cost 与服务
// 当前配置不一致，耗时就对不上，白防了
var (
	dummyHash     []byte
	dummyHashOnce sync.Once
)

func getDummyHash() []byte {
	dummyHashOnce.Do(func() {
		hash, err := bcrypt.GenerateFromPassword([]byte("placeholder-for-timing-equalization"), bcrypt.DefaultCost)
		if err != nil {
			// bcrypt 不会因为输入内容失败，走不到这里
			log.Printf("Warning: 生成占位 hash 失败: %v", err)
		}
		dummyHash = hash
	})
	return dummyHash
}

// Register 注册并直接签发了登录态（注册完不用再登一次）
func (s *AuthService) Register(req *dto.RegisterRequest) (*dto.TokenResponse, error) {
	username := strings.TrimSpace(req.Username)
	if utf8.RuneCountInString(username) < minUsernameLen {
		return nil, fmt.Errorf("%w：至少 %d 个字符", ErrInvalidUsername, minUsernameLen)
	}
	if err := validatePassword(req.Password); err != nil {
		return nil, err
	}

	// 先查一次给出友好提示。真正的唯一性保证靠 users.username 上的 uniqueIndex ——
	// 查与插之间存在竞态，并发注册同名时靠数据库兜底，下面捕获重复键错误
	var count int64
	if err := config.DB.Model(&models.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, ErrUsernameTaken
	}

	user := models.User{
		Username: username,
		Nickname: strings.TrimSpace(req.Nickname),
		Status:   "active",
		// 角色一律是普通用户。管理员只能手工 SQL 指定，
		// 避免"第一个注册的人自动变管理员"这类隐式提权（沿用 call-back 的约定）
		Role: models.UserRoleUser,
	}
	if err := user.SetPassword(req.Password); err != nil {
		return nil, err
	}

	if err := config.DB.Create(&user).Error; err != nil {
		// 上面的 Count 与这里的 Create 之间存在竞态：两个请求可能同时通过检查。
		// 真正的唯一性由 users.username 上的 uniqueIndex 保证，这里只是把
		// 数据库的报错翻译成一个能看懂的业务错误
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}

	return s.tokens.Issue(&user, "")
}

// Login 校验用户名密码并签发登录态
func (s *AuthService) Login(req *dto.LoginRequest) (*dto.TokenResponse, error) {
	var user models.User
	err := config.DB.Where("username = ?", strings.TrimSpace(req.Username)).First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// **关键**：用户不存在时也要跑一次 bcrypt 比对。
		//
		// 不跑的话，这条路径比"密码错误"快得多（bcrypt 是故意设计的慢），
		// 攻击者就能靠响应时间筛出哪些用户名真实存在。
		// 拿一个固定的占位 hash 比对，两条路径耗时一致
		_ = bcrypt.CompareHashAndPassword(getDummyHash(), []byte(req.Password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if !user.CheckPassword(req.Password) {
		return nil, ErrInvalidCredentials
	}

	// 密码对但账号被禁用：这时才明确告知"被禁用"是安全的 ——
	// 能走到这里说明对方已经知道正确密码了，不存在用户名枚举问题
	if !user.IsActive() {
		s.tokens.RevokeAll(user.ID)
		return nil, ErrAccountDisabled
	}

	return s.tokens.Issue(&user, strings.TrimSpace(req.ClientID))
}

// GetUser 取用户信息。供 /auth/me 使用
func (s *AuthService) GetUser(userID uint) (*dto.UserInfo, error) {
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		return nil, ErrTokenInvalid
	}
	info := ToUserInfo(&user)
	return &info, nil
}

// validatePassword 按**字节**校验密码长度。
//
// 用字节而不是字符，是因为 bcrypt 的 72 字节截断就是按字节的：
// 一个 30 个汉字的密码是 90 字节，已经超了，而按字符算是"才 30 个"
func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("%w：至少 %d 位", ErrWeakPassword, minPasswordLen)
	}
	if len(password) > dto.MaxPasswordBytes {
		return fmt.Errorf("%w：不能超过 %d 字节（约 %d 个汉字）",
			ErrWeakPassword, dto.MaxPasswordBytes, dto.MaxPasswordBytes/3)
	}
	return nil
}
