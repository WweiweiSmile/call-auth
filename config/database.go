package config

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"call-auth/models"
)

var DB *gorm.DB

// InitDB 连接数据库。
//
// 与 call-back 不同，这里**不创建数据库**：call-auth 复用 call-back 的库，
// 库应该已经存在。连不上就直接失败，比"顺手建一个空库然后发现 users 表没有"
// 要好定位得多
func InitDB() error {
	if AppConfig == nil {
		return fmt.Errorf("配置未加载，请先调用 LoadConfig()")
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		AppConfig.DBUser,
		AppConfig.DBPassword,
		AppConfig.DBHost,
		AppConfig.DBPort,
		AppConfig.DBName,
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
		// 把驱动的原生错误翻译成 gorm.ErrDuplicatedKey 这类统一错误。
		// 不开启的话，判断唯一键冲突只能去匹配错误信息里的 "1062"，
		// 那就把业务代码焊死在 MySQL 上了（测试用 SQLite 时立刻会暴露）
		TranslateError: true,
	})
	if err != nil {
		return fmt.Errorf("连接数据库 %s 失败: %w", AppConfig.DBName, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取底层连接池失败: %w", err)
	}
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	DB = db
	log.Printf("已连接数据库 %s", AppConfig.DBName)
	return nil
}

// Migrate 建认证中心**自己的**表，并自检 users 表存在。
//
// 这里绝不 AutoMigrate users：那张表归 call-back 管。两个服务同时对同一张表
// 做 AutoMigrate 会互相覆盖列定义 —— 谁启动得晚，谁的模型就是"对的"，
// 而另一边的字段会被悄悄改掉
func Migrate() error {
	// 认证中心**自己的**表。users 不在这里 —— 那张表归 call-back 管
	if err := DB.AutoMigrate(
		&models.RefreshToken{},
		&models.SSOClient{},
		&models.SSOTicket{},
	); err != nil {
		return fmt.Errorf("建表失败: %w", err)
	}

	// 启动自检：users 表必须已经由 call-back 建好。
	// 不检查的话，第一次有人登录才会报"表不存在"，而那时候你已经在查别的问题了
	if !DB.Migrator().HasTable("users") {
		return fmt.Errorf(
			"数据库 %s 里没有 users 表。认证中心复用 call-back 的 users 表，"+
				"请确认 DB_NAME 指向的是 call-back 的库，且 call-back 至少启动过一次",
			AppConfig.DBName)
	}

	seedSSOClients()

	log.Println("数据表检查通过")
	return nil
}

// seedSSOClients 同步应用注册表。
//
// 与 call-back 的 seedLeakTags 同一套做法：启动时补齐 / 更新内容，但**不动
// is_active** —— 手动停用过的 client 不能被启动逻辑重新打开，否则"临时禁用某个
// 应用"就做不到了。
//
// 注意回调地址会被这里覆盖回默认值：改地址要改 `models.DefaultSSOClients` 并重启，
// 直接在数据库里改会在下次启动时被冲掉
func seedSSOClients() {
	created, updated := 0, 0

	for i := range models.DefaultSSOClients {
		seed := models.DefaultSSOClients[i]

		var existing models.SSOClient
		err := DB.Where("client_id = ?", seed.ClientID).First(&existing).Error
		if err != nil {
			if err := DB.Create(&seed).Error; err != nil {
				log.Printf("Warning: 写入 SSO client %s 失败: %v", seed.ClientID, err)
				continue
			}
			created++
			continue
		}

		existing.Name = seed.Name
		existing.RedirectURIs = seed.RedirectURIs
		if err := DB.Save(&existing).Error; err != nil {
			log.Printf("Warning: 更新 SSO client %s 失败: %v", seed.ClientID, err)
			continue
		}
		updated++
	}

	log.Printf("SSO clients 同步完成：新建 %d，更新 %d", created, updated)
}
