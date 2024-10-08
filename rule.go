package waf

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
)

func (w *CaddyWaf) loadArgsRule(rulePath string) error {
	var err error
	w.ArgsRule, err = loadRule(rulePath)

	if len(w.ArgsRule) > 0 {
		var res []*regexp.Regexp
		for _, rule := range w.ArgsRule {
			reg, err := regexp.Compile(rule)
			if err != nil {
				continue
			}
			res = append(res, reg)
		}
		w.ArgsReRule = res
	}

	return err
}

func (w *CaddyWaf) loadPostRule(rulePath string) error {
	var err error
	w.PostRule, err = loadRule(rulePath)

	if len(w.PostRule) > 0 {
		var res []*regexp.Regexp
		for _, rule := range w.PostRule {
			reg, err := regexp.Compile(rule)
			if err != nil {
				continue
			}
			res = append(res, reg)
		}
		w.PostReRule = res
	}
	return err
}

func (w *CaddyWaf) loadUserAgentRule(rulePath string) error {
	var err error
	w.UserAgentRule, err = loadRule(rulePath)

	if len(w.UserAgentRule) > 0 {
		var res []*regexp.Regexp
		for _, rule := range w.UserAgentRule {
			reg, err := regexp.Compile(rule)
			if err != nil {
				continue
			}
			res = append(res, reg)
		}
		w.UserAgentReRule = res
	}
	return err
}

func (w *CaddyWaf) loadIpRule(rulePath string, isBlock bool) error {
	ipRule, err := loadRule(rulePath)
	if isBlock {
		w.IpBlockRule = ipRule
	} else {
		w.IpAllowRule = ipRule
	}
	return err

}

func loadRule(rulePath string) ([]string, error) {
	file, err := os.Open(rulePath)
	if err != nil {
		return nil, fmt.Errorf("parsing rule file error: %v", err)
	}
	rule := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rule = append(rule, scanner.Text())
	}

	return rule, nil
}

// detectAllowIp
func (w *CaddyWaf) detectIp(ipAddr string, isBlock bool) bool {

	var ipRule []string
	if isBlock {
		ipRule = w.IpBlockRule
	} else {
		ipRule = w.IpAllowRule
	}
	ip := net.ParseIP(ipAddr)
	for _, rule := range ipRule {
		_, ipNet, err := net.ParseCIDR(rule)
		if err != nil {
			if ip.Equal(net.ParseIP(rule)) {
				return true
			}
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// detectRequestArgs
func (w *CaddyWaf) detectRequestArgs(r *http.Request) bool {
	for _, reg := range w.ArgsReRule {
		if reg.MatchString(r.RequestURI) {
			return true
		}
	}
	return false
}

// detectRequestBody
func (w *CaddyWaf) detectRequestBody(r *http.Request) bool {

	//仅拦截post 类型的请求, 检测body实体里面是否有违规内容
	if r.Method != "POST" {
		return false
	}

	body, _ := io.ReadAll(r.Body)
	r.Body.Close() //  must close
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	if len(body) == 0 {
		return false
	}

	for _, reg := range w.PostReRule {
		if reg.MatchString(string(body)) {
			return true
		}
	}
	return false
}

// detectUserAgent
func (w *CaddyWaf) detectUserAgent(r *http.Request) bool {
	userAgent := r.UserAgent()
	for _, reg := range w.UserAgentReRule {
		if reg.MatchString(userAgent) {
			return true
		}
	}

	return false
}

// redirectIntercept Intercept request
func (w *CaddyWaf) redirectIntercept(rw http.ResponseWriter) error {
	var tpl *template.Template
	tpl, _ = template.New("default_listing").Parse(defaultWafTemplate)
	return tpl.Execute(rw, nil)
}
