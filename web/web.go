// Package web 装认证中心自己的页面。
//
// 只有登录页一个页面 —— 它必须住在认证中心**自己域名下**：跨域时前端 JS
// 无法为别的域写 cookie，能种下 auth 域会话 cookie 的只有 auth 域自己（§4.5）。
//
// 用 embed 而不是读磁盘上的模板目录：二进制到哪页面就在哪，
// 不会出现「部署时漏拷 templates 目录、登录页 500」这种事故
package web

import "embed"

//go:embed templates/*.html
var Templates embed.FS
