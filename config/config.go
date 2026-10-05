package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	// ---------- 数据库 ----------
	// 刻意连**和 call-back 同一个库**：users 表是身份权威源，而它的 id 被
	// 所有业务表当外键引用。把表搬走要改遍全库外键 + 停服迁移，
	// 不值得 —— 见《认证中心设计文档》§4.4
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	ServerPort string

	// ---------- 密钥 ----------
	// AuthPrivateKeyPath RS256 私钥路径。**必填，没有默认值**：
	// 密钥如果有兜底，漏配就不会报错，服务会拿着一个人尽皆知的密钥正常跑起来。
	// 对密钥来说启动失败是唯一可接受的失败方式
	AuthPrivateKeyPath string

	// ---------- 令牌 ----------
	// AuthIssuer 签发者。各服务验签时校验它，防止别处签的 token 混进来
	AuthIssuer string
	// AuthAudiences 允许使用本服务签发的 token 的服务列表。
	// 各服务验签时校验自己在不在里面
	AuthAudiences []string
	// AccessTokenTTLSeconds 访问令牌有效期，默认 15 分钟。
	// 短过期是无状态 JWT 能接受的原因之一：登出最多 15 分钟后彻底生效
	AccessTokenTTLSeconds int
	// RefreshTokenTTLSeconds 刷新令牌有效期，默认 14 天
	RefreshTokenTTLSeconds int
	// LeewaySeconds 时钟偏差容忍，默认 60 秒
	LeewaySeconds int

	// ---------- CORS ----------
	CORSOrigins []string
}

var AppConfig *Config

func LoadConfig() error {
	envFile, tried, err := locateEnvFile()
	if err != nil {
		return err
	}
	if envFile == "" {
		// 没有 .env 是合法的部署方式（全靠环境变量），不是错误。
		// 但把找过哪些地方写进启动日志 ——「.env 明明放了却没生效」这类问题
		// 全靠这一行定位
		log.Printf("Warning: 没找到 .env（找过 %v），改用环境变量", tried)
	} else if err := godotenv.Load(envFile); err != nil {
		return fmt.Errorf("加载 %s 失败: %w", envFile, err)
	}

	privateKeyPath, err := requireEnv("AUTH_PRIVATE_KEY_PATH")
	if err != nil {
		return err
	}

	issuer := GetEnv("AUTH_ISSUER", "call-auth")
	// 认证中心自己也是个资源服务（/auth/me 需要鉴权），所以它必须出现在 aud 列表里。
	// 靠配置去记住这件事迟早会忘，忘了的表现是 /auth/me 稳定 401 —— 很难往这上面想
	audiences := ensureContains(splitAndTrim(GetEnv("AUTH_AUDIENCES", "call-back,learn-daily")), issuer)

	AppConfig = &Config{
		DBHost:     GetEnv("DB_HOST", "127.0.0.1"),
		DBPort:     GetEnv("DB_PORT", "3306"),
		DBUser:     GetEnv("DB_USER", "root"),
		DBPassword: GetEnv("DB_PASSWORD", ""),
		DBName:     GetEnv("DB_NAME", "call_game"),

		ServerPort: GetEnv("SERVER_PORT", "8020"),

		AuthPrivateKeyPath: privateKeyPath,

		AuthIssuer:             issuer,
		AuthAudiences:          audiences,
		AccessTokenTTLSeconds:  GetEnvInt("ACCESS_TOKEN_TTL_SECONDS", 900),
		RefreshTokenTTLSeconds: GetEnvInt("REFRESH_TOKEN_TTL_SECONDS", 14*24*3600),
		LeewaySeconds:          GetEnvInt("JWT_LEEWAY_SECONDS", 60),

		CORSOrigins: splitAndTrim(GetEnv("CORS_ORIGINS", "")),
	}

	log.Printf("配置加载完成：issuer=%s audiences=%v access_ttl=%ds",
		AppConfig.AuthIssuer, AppConfig.AuthAudiences, AppConfig.AccessTokenTTLSeconds)
	return nil
}

// requireEnv 读一个**必须存在**的环境变量。缺失时返回错误，由 LoadConfig 中止启动。
//
// 为什么不给默认值：密钥这类东西一旦有默认值，漏配就不会报错——服务会带着一个
// 写在源码里的、公开的密钥正常跑起来，任何人都能伪造 token，而且没有任何迹象。
// 对密钥来说，**启动失败是唯一可接受的失败方式**：它 5 秒内就能被发现，
// 而静默兜底可能半年都没人察觉
func requireEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf(
			"缺少必需的环境变量 %s。它没有默认值：漏配时用兜底密钥启动，"+
				"等于任何人都能伪造登录态。请在 .env 里配置", key)
	}
	return value, nil
}

// ensureContains 保证 value 在 list 里，不在就追加
func ensureContains(list []string, value string) []string {
	for _, item := range list {
		if item == value {
			return list
		}
	}
	return append(list, value)
}

// splitAndTrim 把逗号分隔的配置切开并去掉空白项，顺带裁掉每项的首尾空白
func splitAndTrim(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// envFileOverride 显式指定 .env 路径的环境变量名。
//
// 为什么需要它：`godotenv.Load()` 不带参数时只认进程的 CWD，而部署环境
// （宝塔面板 / systemd）拉起的进程 CWD 往往不是项目目录 —— 于是整个 .env
// **静默失效**，服务用一堆默认值起来、连到错误的数据库，而且不报任何错。
// 这个变量让部署方可以明确指定路径，不依赖启动方式
const envFileOverride = "ENV_FILE"

// candidateEnvFiles 返回 .env 的候选位置，按优先级排列。
// 可执行文件目录排在 CWD 之前：二进制所在目录更接近「应用的家」，
// 而 CWD 只是启动方式的副产物
func candidateEnvFiles() []string {
	exe, err := os.Executable()
	if err != nil {
		return []string{".env"}
	}
	return []string{filepath.Join(filepath.Dir(exe), ".env"), ".env"}
}

// locateEnvFile 定位 .env 文件。返回（命中的路径，尝试过的候选，错误）。
//
// ENV_FILE 显式指定时**只认它**，读不到就报错 —— 部署方明明配了路径、
// 服务却按默认值起来，是比启动失败难查得多的问题
func locateEnvFile() (string, []string, error) {
	if override := strings.TrimSpace(os.Getenv(envFileOverride)); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", nil, fmt.Errorf("%s 指向的 %s 读不到: %w", envFileOverride, override, err)
		}
		return override, nil, nil
	}

	candidates := candidateEnvFiles()
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil, nil
		}
	}
	return "", candidates, nil
}

func GetEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetEnvInt 读整数配置。非法值与空值一律退回默认值，
// 避免一个手滑的环境变量让服务起不来
func GetEnvInt(key string, defaultValue int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("Warning: %s=%q 不是合法整数，使用默认值 %d", key, raw, defaultValue)
		return defaultValue
	}
	return value
}
