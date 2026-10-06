package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 用户角色。与 call-back 保持一致
const (
	UserRoleUser  = "user"
	UserRoleAdmin = "admin"
)

// User 用户表。
//
// **这张表的定义必须与 call-back/models/user.go 逐字段一致** —— 两个服务连的是
// 同一个库的同一张表。任何一边改了字段，另一边要同步改，否则 GORM 读写会错列。
// 改动前先看《认证中心设计文档》§4.4
//
// 约定：**只有认证中心能写这张表**。call-back 侧应删掉所有写入代码
type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Username  string         `json:"username" gorm:"size:100;uniqueIndex;not null;comment:用户名"`
	Nickname  string         `json:"nickname" gorm:"size:100;comment:昵称"`
	Avatar    string         `json:"avatar" gorm:"size:500;comment:头像URL"`
	Password  string         `json:"-" gorm:"size:255;not null;comment:密码"`
	Status    string         `json:"status" gorm:"size:20;default:'active';comment:状态: active-正常, inactive-禁用"`
	Role      string         `json:"role" gorm:"size:20;not null;default:'user';comment:角色: user-普通用户, admin-系统管理"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

func (User) TableName() string {
	return "users"
}

// IsActive 账号是否可用
func (u *User) IsActive() bool {
	return u.Status == "active"
}

// IsAdmin 是否管理员
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

// SetPassword 设置密码（bcrypt 加密）。
// 与 call-back 用同一套算法，所以从 call-back 迁过来的 hash 可以直接沿用，
// 用户不用重置密码
func (u *User) SetPassword(password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashed)
	return nil
}

// CheckPassword 校验密码
func (u *User) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}
