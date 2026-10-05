package services

import (
	"path/filepath"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"call-auth/config"
	"call-auth/models"
	"call-auth/utils"
)

// setupTest 把 config.DB / config.AppConfig 指到一个临时 SQLite 上。
//
// service 读的是包级变量 config.DB，所以测试直接替换它即可 ——
// 不需要为了可测性给每个 service 加一个 db 字段（那会把生产代码改复杂，
// 只为了让测试好写）
func setupTest(t *testing.T) *TokenService {
	t.Helper()

	// 用临时**文件**而不是 :memory: —— 内存库在连接池下每条连接看到的
	// 是各自独立的库，会随机出现"表不存在"
	dsn := filepath.Join(t.TempDir(), "test.db")
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}); err != nil {
		t.Fatal(err)
	}

	config.DB = db
	config.AppConfig = &config.Config{
		AuthIssuer:             "call-auth",
		AuthAudiences:          []string{"call-auth", "call-back"},
		AccessTokenTTLSeconds:  900,
		RefreshTokenTTLSeconds: 14 * 24 * 3600,
		LeewaySeconds:          60,
	}

	keys, err := utils.LoadOrCreateKeyPair(filepath.Join(t.TempDir(), "private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return NewTokenService(keys)
}

func createUser(t *testing.T, username string) *models.User {
	t.Helper()

	user := models.User{Username: username, Status: "active", Role: models.UserRoleUser}
	if err := user.SetPassword("password123"); err != nil {
		t.Fatal(err)
	}
	if err := config.DB.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	return &user
}

// refreshRows 取某用户的全部 refresh token 行，方便断言"全被吊销了"
func refreshRows(t *testing.T, userID uint) []models.RefreshToken {
	t.Helper()

	var rows []models.RefreshToken
	if err := config.DB.Where("user_id = ?", userID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}
