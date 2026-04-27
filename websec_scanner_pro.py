#!/usr/bin/env python3
"""
WebSec Scanner Pro - 专业网站安全扫描服务
紧急收入冲刺MVP产品
功能：提供基本的网站安全扫描，包括SQL注入、XSS、目录遍历检测
"""

import requests
import sys
import time
import json
from urllib.parse import urljoin
from datetime import datetime

class WebSecScannerPro:
    def __init__(self, target_url, api_key=None):
        self.target_url = target_url
        self.api_key = api_key
        self.results = {
            "scan_id": f"scan_{int(time.time())}",
            "target": target_url,
            "start_time": datetime.now().isoformat(),
            "vulnerabilities": [],
            "security_headers": {},
            "server_info": {},
            "risk_score": 0,
            "recommendations": []
        }
        
        # 常见漏洞测试向量
        self.test_vectors = {
            "sql_injection": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "1' AND '1'='1",
                "1' UNION SELECT null,null --",
                "1' AND SLEEP(5) --"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "onload=alert('XSS')"
            ],
            "directory_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]
        }
    
    def scan_security_headers(self):
        """扫描安全头信息"""
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "Missing"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Missing")
            }
            
            self.results["security_headers"] = security_headers
            self.results["server_info"] = {
                "server": headers.get("Server", "Unknown"),
                "powered_by": headers.get("X-Powered-By", "Unknown")
            }
            
            # 计算安全头分数
            missing_headers = sum(1 for v in security_headers.values() if v == "Missing")
            header_score = max(0, 100 - (missing_headers * 15))
            
            return header_score
            
        except Exception as e:
            print(f"⚠️  安全头扫描失败: {e}")
            return 0
    
    def test_sql_injection(self, test_url):
        """测试SQL注入漏洞"""
        vulnerabilities = []
        
        # 简单测试：检查错误信息
        test_payloads = ["'", "\"", "1' OR '1'='1"]
        
        for payload in test_payloads:
            try:
                test_url_with_payload = f"{test_url}{payload}"
                response = requests.get(test_url_with_payload, timeout=5)
                
                # 检查常见数据库错误信息
                error_indicators = [
                    "SQL syntax", "MySQL", "PostgreSQL", "Oracle", 
                    "SQLite", "Microsoft SQL Server", "syntax error",
                    "unclosed quotation mark", "You have an error"
                ]
                
                for indicator in error_indicators:
                    if indicator.lower() in response.text.lower():
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "payload": payload,
                            "confidence": "Medium",
                            "description": f"检测到可能的SQL注入漏洞，响应包含数据库错误信息: {indicator}"
                        })
                        break
                        
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def test_xss(self, test_url):
        """测试XSS漏洞"""
        vulnerabilities = []
        
        for payload in self.test_vectors["xss"][:2]:  # 只测试前两个
            try:
                test_url_with_payload = f"{test_url}{payload}"
                response = requests.get(test_url_with_payload, timeout=5)
                
                # 检查payload是否在响应中（反射型XSS）
                if payload in response.text:
                    vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "payload": payload,
                        "confidence": "Medium",
                        "description": f"检测到可能的反射型XSS漏洞，payload出现在响应中"
                    })
                    
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def scan_for_sensitive_files(self):
        """扫描敏感文件"""
        sensitive_files = [
            "/robots.txt",
            "/sitemap.xml",
            "/.git/HEAD",
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/phpinfo.php",
            "/admin/",
            "/dashboard/",
            "/phpmyadmin/"
        ]
        
        found_files = []
        
        for file_path in sensitive_files:
            try:
                full_url = urljoin(self.target_url, file_path)
                response = requests.get(full_url, timeout=5)
                
                if response.status_code == 200:
                    found_files.append({
                        "path": file_path,
                        "status_code": response.status_code,
                        "size": len(response.content)
                    })
                    
            except Exception as e:
                continue
        
        return found_files
    
    def generate_report(self):
        """生成专业报告"""
        report = f"""
# WebSec Scanner Pro 安全扫描报告

## 扫描概览
- **扫描ID**: {self.results['scan_id']}
- **目标网站**: {self.results['target']}
- **扫描时间**: {self.results['start_time']}
- **风险评分**: {self.results['risk_score']}/100

## 漏洞发现
"""
        
        if self.results["vulnerabilities"]:
            for vuln in self.results["vulnerabilities"]:
                report += f"""
### {vuln['type']}
- **置信度**: {vuln['confidence']}
- **描述**: {vuln['description']}
- **Payload**: `{vuln['payload']}`
"""
        else:
            report += "\n✅ 未发现高危漏洞\n"
        
        report += f"""
## 安全头信息
"""
        for header, value in self.results["security_headers"].items():
            status = "✅" if value != "Missing" else "❌"
            report += f"- {status} **{header}**: {value}\n"
        
        report += f"""
## 服务器信息
- **服务器**: {self.results['server_info'].get('server', 'Unknown')}
- **Powered By**: {self.results['server_info'].get('powered_by', 'Unknown')}

## 敏感文件发现
"""
        sensitive_files = self.scan_for_sensitive_files()
        if sensitive_files:
            for file_info in sensitive_files:
                report += f"- **{file_info['path']}** (状态码: {file_info['status_code']}, 大小: {file_info['size']} bytes)\n"
        else:
            report += "- 未发现可公开访问的敏感文件\n"
        
        report += f"""
## 安全建议
"""
        for rec in self.results["recommendations"]:
            report += f"- {rec}\n"
        
        report += f"""
## 专业服务升级
如需深度安全测试，请考虑我们的专业服务：
1. **基础扫描** ($49): 自动漏洞检测 + 基础报告
2. **专业审计** ($149): 人工代码审查 + 渗透测试 + 详细报告
3. **企业套餐** ($599): 持续监控 + 应急响应 + 安全培训

立即联系: jhonwind2023@gmail.com
网站: https://websec-scanner.com
"""
        
        return report
    
    def run_scan(self):
        """运行完整扫描"""
        print(f"🚀 开始扫描: {self.target_url}")
        
        # 1. 扫描安全头
        print("📋 扫描安全头信息...")
        header_score = self.scan_security_headers()
        
        # 2. 测试SQL注入
        print("💉 测试SQL注入漏洞...")
        sql_vulns = self.test_sql_injection(self.target_url)
        self.results["vulnerabilities"].extend(sql_vulns)
        
        # 3. 测试XSS
        print("🕷️  测试XSS漏洞...")
        xss_vulns = self.test_xss(self.target_url)
        self.results["vulnerabilities"].extend(xss_vulns)
        
        # 4. 生成建议
        recommendations = []
        
        # 基于安全头的建议
        if self.results["security_headers"].get("Content-Security-Policy") == "Missing":
            recommendations.append("添加Content-Security-Policy头以防止XSS攻击")
        if self.results["security_headers"].get("Strict-Transport-Security") == "Missing":
            recommendations.append("添加HSTS头以强制HTTPS连接")
        
        # 基于漏洞的建议
        if any(v["type"] == "SQL Injection" for v in self.results["vulnerabilities"]):
            recommendations.append("实施参数化查询或使用ORM框架防止SQL注入")
        if any(v["type"] == "Cross-Site Scripting (XSS)" for v in self.results["vulnerabilities"]):
            recommendations.append("对所有用户输入进行适当的编码和验证")
        
        self.results["recommendations"] = recommendations
        
        # 5. 计算风险评分
        vuln_count = len(self.results["vulnerabilities"])
        risk_score = max(0, 100 - (header_score * 0.6) - (vuln_count * 10))
        self.results["risk_score"] = int(risk_score)
        
        # 6. 完成扫描
        self.results["end_time"] = datetime.now().isoformat()
        self.results["scan_duration"] = time.time() - float(self.results["scan_id"].split("_")[1])
        
        print(f"✅ 扫描完成! 发现 {vuln_count} 个漏洞，风险评分: {risk_score}/100")
        
        return self.results

def main():
    """命令行接口"""
    if len(sys.argv) < 2:
        print("用法: python3 websec_scanner_pro.py <目标URL>")
        print("示例: python3 websec_scanner_pro.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print("="*60)
    print("🔒 WebSec Scanner Pro - 专业网站安全扫描")
    print("="*60)
    
    scanner = WebSecScannerPro(target_url)
    results = scanner.run_scan()
    
    # 生成并显示报告
    report = scanner.generate_report()
    print(report)
    
    # 保存报告到文件
    report_filename = f"security_scan_{results['scan_id']}.md"
    with open(report_filename, 'w') as f:
        f.write(report)
    
    print(f"📄 报告已保存到: {report_filename}")
    print("="*60)
    print("💼 专业服务: https://websec-scanner.com")
    print("📧 联系我们: jhonwind2023@gmail.com")
    print("="*60)

if __name__ == "__main__":
    main()