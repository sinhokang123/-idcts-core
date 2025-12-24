"""
IDCTS URL 분석 모듈
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import Optional


def extract_domain(url: str) -> str:
    """URL에서 도메인 추출"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""


def analyze_url(target_url: str, timeout: int = 10) -> dict:
    """
    URL 분석 - HTML에서 관련 URL/도메인 추출
    """
    result = {
        "domains": [],
        "urls": [],
        "iframes": [],
        "videos": [],
        "images": [],
        "scripts": [],
        "error": None
    }
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        response = requests.get(target_url, headers=headers, timeout=timeout, verify=False)
        html = response.text
        
        soup = BeautifulSoup(html, 'html.parser')
        
        domains_set = set()
        urls_set = set()
        
        # 메인 도메인 추가
        main_domain = extract_domain(target_url)
        if main_domain:
            domains_set.add(main_domain)
        
        # iframe 추출
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            if src:
                full_url = urljoin(target_url, src)
                result["iframes"].append(full_url)
                urls_set.add(full_url)
                domain = extract_domain(full_url)
                if domain:
                    domains_set.add(domain)
        
        # video/source 추출
        for video in soup.find_all(['video', 'source']):
            src = video.get('src', '')
            if src:
                full_url = urljoin(target_url, src)
                result["videos"].append(full_url)
                urls_set.add(full_url)
                domain = extract_domain(full_url)
                if domain:
                    domains_set.add(domain)
        
        # img 추출
        for img in soup.find_all('img'):
            src = img.get('src', '')
            if src and not src.startswith('data:'):
                full_url = urljoin(target_url, src)
                result["images"].append(full_url)
                urls_set.add(full_url)
                domain = extract_domain(full_url)
                if domain:
                    domains_set.add(domain)
        
        # script 추출
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src:
                full_url = urljoin(target_url, src)
                result["scripts"].append(full_url)
                urls_set.add(full_url)
                domain = extract_domain(full_url)
                if domain:
                    domains_set.add(domain)
        
        # a href 추출
        for a in soup.find_all('a'):
            href = a.get('href', '')
            if href and href.startswith('http'):
                urls_set.add(href)
                domain = extract_domain(href)
                if domain:
                    domains_set.add(domain)
        
        # URL 패턴으로 추가 추출
        url_pattern = r'https?://[^\s"\'>]+'
        found_urls = re.findall(url_pattern, html)
        for url in found_urls:
            urls_set.add(url)
            domain = extract_domain(url)
            if domain:
                domains_set.add(domain)
        
        result["domains"] = list(domains_set)
        result["urls"] = list(urls_set)
        
    except requests.exceptions.Timeout:
        result["error"] = "Request timeout"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    
    return result
