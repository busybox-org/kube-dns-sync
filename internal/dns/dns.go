package dns

import (
	"errors"
	"net/url"
	"strings"
)

type Config struct {
	Ak         string
	SK         string
	Type       string
	Host       string
	Addr       string
	Args       url.Values
	domainName string
	subDomain  string
}

type IDNS interface {
	Init(conf *Config) error
	// 添加或更新IPv4/IPv6记录
	AddUpdateDomainRecords() error
}

func New(provider string) (IDNS, error) {
	switch provider {
	case "cloudflare":
		return &Cloudflare{}, nil
	default:
		return nil, errors.New("no matching DNS provider")
	}
}

var staticMainDomains = []string{"com.cn", "org.cn", "net.cn", "ac.cn", "eu.org"}

func (c *Config) parseDomains() error {
	domainStr := strings.TrimSpace(c.Host)
	if domainStr != "" {
		sp := strings.Split(domainStr, ".")
		length := len(sp)
		if length <= 1 {
			return errors.New("incorrect domain name")
		}
		// 处理域名
		c.domainName = sp[length-2] + "." + sp[length-1]
		// 如包含在org.cn等顶级域名下，后三个才为用户主域名
		for _, staticMainDomain := range staticMainDomains {
			// 移除 domain.DomainName 的查询字符串以便与 staticMainDomain 进行比较。
			// 查询字符串是 URL ? 后面的部分。
			// 查询字符串的存在会导致顶级域名无法与 staticMainDomain 精确匹配，从而被误认为二级域名。
			// 示例："com.cn?param=value" 将被替换为 "com.cn"。
			// https://github.com/jeessy2/ddns-go/issues/714
			if staticMainDomain == strings.Split(c.domainName, "?")[0] {
				c.domainName = sp[length-3] + "." + c.domainName
				break
			}
		}

		domainLen := len(domainStr) - len(c.domainName)
		if domainLen > 0 {
			c.subDomain = domainStr[:domainLen-1]
		} else {
			c.subDomain = domainStr[:domainLen]
		}
	}
	return nil
}

// GetFullDomain 获得全部的，子域名
func (c *Config) getFullDomain() string {
	if c.subDomain != "" {
		return c.subDomain + "." + c.domainName
	}
	return "@" + "." + c.domainName
}

// GetSubDomain 获得子域名，为空返回@
// 阿里云/腾讯云/dnspod/namecheap 需要
func (c *Config) getSubDomain() string {
	if c.subDomain != "" {
		return c.subDomain
	}
	return "@"
}
