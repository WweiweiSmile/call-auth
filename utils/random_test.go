package utils

import (
	"encoding/hex"
	"testing"
)

func TestOpaqueTokenShape(t *testing.T) {
	plain, hash := NewOpaqueToken()

	// 32 字节十六进制 = 64 个字符
	if len(plain) != 64 {
		t.Errorf("明文长度应为 64，实际 %d", len(plain))
	}
	if _, err := hex.DecodeString(plain); err != nil {
		t.Errorf("明文应是十六进制: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("sha256 十六进制长度应为 64，实际 %d", len(hash))
	}
	if plain == hash {
		t.Error("存进库的必须是 hash，不能是明文")
	}
}

func TestOpaqueTokensAreUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		plain, _ := NewOpaqueToken()
		if seen[plain] {
			t.Fatalf("第 %d 次生成撞上了重复的 token —— 随机源有问题", i)
		}
		seen[plain] = true
	}
}

func TestHashTokenIsDeterministic(t *testing.T) {
	plain, hash := NewOpaqueToken()

	// 校验时是拿明文重新算 hash 去查库的，算法必须稳定。
	// 换算法（或加盐）会让所有已发出的 refresh token 全部失效
	for i := 0; i < 3; i++ {
		if got := HashToken(plain); got != hash {
			t.Fatalf("同输入两次 hash 不一致：%q != %q", got, hash)
		}
	}
}

func TestTokenIDIsUnique(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		id := NewTokenID()
		if len(id) != 32 {
			t.Fatalf("jti 应是 16 字节十六进制（32 字符），实际 %d", len(id))
		}
		if seen[id] {
			t.Fatal("jti 重复")
		}
		seen[id] = true
	}
}
