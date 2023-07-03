package dns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/xmapst/kube-dns-sync/internal/utils"
	"k8s.io/klog/v2"
)

const (
	zonesAPI string = "https://api.cloudflare.com/client/v4/zones"
)

// Cloudflare Cloudflare实现
type Cloudflare struct {
	conf *Config
	TTL  int
}

// CloudflareZonesResp cloudflare zones返回结果
type CloudflareZonesResp struct {
	CloudflareStatus
	Result []struct {
		ID     string
		Name   string
		Status string
		Paused bool
	}
}

// CloudflareRecordsResp records
type CloudflareRecordsResp struct {
	CloudflareStatus
	Result []CloudflareRecord
}

// CloudflareRecord 记录实体
type CloudflareRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// CloudflareStatus 公共状态
type CloudflareStatus struct {
	Success  bool
	Messages []string
}

// Init 初始化
func (cf *Cloudflare) Init(conf *Config) error {
	if conf.Type == "IPV4" {
		conf.Type = "A"
	}
	if conf.Type == "IPV6" {
		conf.Type = "AAAA"
	}
	cf.conf = conf
	cf.TTL, _ = strconv.Atoi(cf.conf.Args.Get("ttl"))
	if cf.TTL == 0 {
		cf.TTL = 1
	}
	return cf.conf.parseDomains()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (cf *Cloudflare) AddUpdateDomainRecords() error {
	return cf.addUpdateDomainRecords()
}

func (cf *Cloudflare) addUpdateDomainRecords() error {
	// get zone
	result, err := cf.getZones()
	if err != nil {
		klog.Errorln(err)
		return err
	}

	var zoneID string
	for _, v := range result.Result {
		if v.Name == cf.conf.domainName && v.Status == "active" {
			zoneID = v.ID
			break
		}
	}
	if zoneID == "" {
		klog.Errorln("failed to get zoneID")
		return errors.New("failed to get zoneID")
	}

	var records CloudflareRecordsResp
	// getDomains 最多更新前50条
	body, err := cf.request(
		"GET",
		fmt.Sprintf(zonesAPI+"/%s/dns_records?type=%s&name=%s&per_page=50", zoneID, cf.conf.Type, cf.conf.Host),
		nil,
	)
	if err != nil {
		klog.Errorln(err)
		return err
	}
	err = json.Unmarshal(body, &records)
	if err != nil {
		klog.Errorln(err)
		return err
	}
	if !records.Success {
		return errors.New(strings.Join(records.Messages, " "))
	}

	if len(records.Result) > 0 {
		// 更新
		err = cf.modify(records, zoneID)
	} else {
		// 新增
		err = cf.create(zoneID)
	}
	if err != nil {
		klog.Errorln(err)
	}
	return err
}

// 创建
func (cf *Cloudflare) create(zoneID string) error {
	record := &CloudflareRecord{
		Type:    cf.conf.Type,
		Name:    cf.conf.Host,
		Content: cf.conf.Addr,
		Proxied: false,
		TTL:     cf.TTL,
	}
	record.Proxied = cf.conf.Args.Get("proxied") == "true"
	var status CloudflareStatus
	body, err := cf.request(
		"POST",
		fmt.Sprintf(zonesAPI+"/%s/dns_records", zoneID),
		record,
	)
	if err != nil {
		klog.Errorln(err)
		return err
	}
	err = json.Unmarshal(body, &status)
	if err != nil {
		klog.Errorln(err)
		return err
	}
	if status.Success {
		klog.Infof("%s --> %s dns record added", cf.conf.Host, cf.conf.Addr)
		return nil
	} else {
		return fmt.Errorf(strings.Join(status.Messages, " "))
	}
}

// 修改
func (cf *Cloudflare) modify(result CloudflareRecordsResp, zoneID string) error {
	for _, record := range result.Result {
		// 相同不修改
		if record.Content == cf.conf.Addr {
			klog.Infof("Your IP %s has not changed, domain name %s", cf.conf.Addr, cf.conf.Host)
			continue
		}
		var status CloudflareStatus
		record.Content = cf.conf.Addr
		record.TTL = cf.TTL
		// 存在参数才修改proxied
		if cf.conf.Args.Has("proxied") {
			record.Proxied = cf.conf.Args.Get("proxied") == "true"
		}
		body, err := cf.request(
			"PUT",
			fmt.Sprintf(zonesAPI+"/%s/dns_records/%s", zoneID, record.ID),
			record,
		)
		if err != nil {
			klog.Errorln(err)
			continue
		}
		err = json.Unmarshal(body, &status)
		if err != nil {
			klog.Errorln(err)
			continue
		}
		if status.Success {
			continue
		} else {
			klog.Errorln(strings.Join(status.Messages, " "))
		}
	}
	return nil
}

// 获得域名记录列表
func (cf *Cloudflare) getZones() (result CloudflareZonesResp, err error) {
	body, err := cf.request(
		"GET",
		fmt.Sprintf(zonesAPI+"?name=%s&status=%s&per_page=%s", cf.conf.domainName, "active", "50"),
		nil,
	)
	if err != nil {
		klog.Errorln(err)
		return
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		klog.Errorln(err)
		return
	}
	return
}

// request 统一请求接口
func (cf *Cloudflare) request(method string, url string, data interface{}) (body []byte, err error) {
	jsonStr := make([]byte, 0)
	if data != nil {
		jsonStr, _ = json.Marshal(data)
	}
	req, err := http.NewRequest(
		method,
		url,
		bytes.NewBuffer(jsonStr),
	)
	if err != nil {
		klog.Errorln(err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cf.conf.SK)
	req.Header.Set("Content-Type", "application/json")

	client := utils.CreateHTTPClient("")
	resp, err := client.Do(req)
	if err != nil {
		klog.Errorln(err)
		return
	}
	return utils.GetHTTPResponseOrg(resp)
}
