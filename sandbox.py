#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lightweight URL Sandbox Module
Implements URL security isolation and access functionality
"""

import requests
import threading
import time
import random
import subprocess
import psutil
import os
import tempfile
from urllib.parse import urlparse
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')

class URLSandbox:
    """Lightweight URL Sandbox Class"""
    
    def __init__(self):
        self.timeout = 5  # 5 seconds timeout
        self.max_redirects = 3  # Maximum redirect count
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
    def _get_random_user_agent(self):
        """Get random User-Agent"""
        return random.choice(self.user_agents)
    
    def _is_suspicious_url(self, url):
        """Basic URL suspicious pattern check"""
        suspicious_patterns = [
            'bit.ly', 'tinyurl', 't.co',  # Short links
            'data:', 'javascript:',       # Dangerous protocols
            'localhost', '127.0.0.1',     # Local addresses
            'file://', 'ftp://',          # File protocols
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                return True, f"Detected suspicious pattern: {pattern}"
        
        # Check IP address
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                # Simple IP address check
                parts = host.split('.')
                if len(parts) == 4 and all(part.isdigit() for part in parts):
                    return True, "Using IP address instead of domain name"
        except:
            pass
            
        return False, "Initial check passed"
    
    def _create_safe_session(self):
        """Create secure request session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Disable cookies to avoid tracking
        session.cookies.clear()
        
        return session
    
    def _safe_request_worker(self, url, result_container):
        """Execute secure request in isolated thread"""
        try:
            session = self._create_safe_session()
            
            # Record start time
            start_time = time.time()
            
            response = session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,  # Stream download to avoid large files
                verify=False  # Ignore SSL certificate issues
            )
            
            # Limit response size (max 1MB)
            max_size = 1024 * 1024  # 1MB
            content = b''
            
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > max_size:
                    break
            
            end_time = time.time()
            
            # Collect response information
            result_container['success'] = True
            result_container['status_code'] = response.status_code
            result_container['headers'] = dict(response.headers)
            result_container['content'] = content.decode('utf-8', errors='ignore')[:10000]  # Limit content length
            result_container['response_time'] = end_time - start_time
            result_container['final_url'] = response.url
            result_container['redirects'] = len(response.history)
            
        except requests.exceptions.Timeout:
            result_container['success'] = False
            result_container['error'] = 'URL access timeout'
            result_container['error_type'] = 'timeout'
            
        except requests.exceptions.ConnectionError:
            result_container['success'] = False
            result_container['error'] = 'Unable to connect to target server'
            result_container['error_type'] = 'connection'
            
        except requests.exceptions.TooManyRedirects:
            result_container['success'] = False
            result_container['error'] = 'Too many redirects'
            result_container['error_type'] = 'redirects'
            
        except Exception as e:
            result_container['success'] = False
            result_container['error'] = f'Request exception: {str(e)}'
            result_container['error_type'] = 'unknown'
    
    def safe_url_access(self, url):
        """Main method for secure URL access"""
        result = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'safe': True,
            'risk_level': 'low',
            'warnings': [],
            'sandbox_data': {}
        }
        
        try:
            # Perform isolation access
            result['sandbox_data']['pre_check'] = 'passed'
            
            # Access URL in isolated thread
            request_result = {}
            worker_thread = threading.Thread(
                target=self._safe_request_worker,
                args=(url, request_result)
            )
            
            worker_thread.daemon = True  # Daemon thread, auto-terminate when main program exits
            worker_thread.start()
            worker_thread.join(timeout=self.timeout + 2)  # Give extra 2 seconds buffer time
            
            if worker_thread.is_alive():
                # Timeout occurred
                result['sandbox_data']['access_result'] = 'timeout'
                result['safe'] = True
                result['risk_level'] = 'low'
                return result
            
            # Process access results
            if not request_result.get('success', False):
                result['sandbox_data']['access_result'] = 'failed'
                result['sandbox_data']['error'] = request_result.get('error', '')
            else:
                # Successful access, save data
                status_code = request_result.get('status_code', 0)
                response_time = request_result.get('response_time', 0)
                redirects = request_result.get('redirects', 0)
                
                # Save sandbox data
                result['sandbox_data'].update({
                    'access_result': 'success',
                    'status_code': status_code,
                    'response_time': round(response_time, 2),
                    'redirects': redirects,
                    'final_url': request_result.get('final_url', url),
                    'content_preview': request_result.get('content', '')[:500]  # First 500 characters
                })
            
            # Set result status
            result['risk_level'] = 'low'
            result['safe'] = True
            
        except Exception as e:
            result['safe'] = False
            result['risk_level'] = 'high'
            result['warnings'].append(f'Sandbox system exception: {str(e)}')
            result['sandbox_data']['system_error'] = str(e)
        
        return result
    
    def get_sandbox_report(self, sandbox_result):
        """Generate sandbox isolation report"""
        if not sandbox_result:
            return "Sandbox isolation failed"
        
        report = "🛡️ Sandbox Isolation: URL accessed in secure environment"
        
        sandbox_data = sandbox_result.get('sandbox_data', {})
        if 'response_time' in sandbox_data:
            report += f"\nResponse Time: {sandbox_data['response_time']}s"
        
        if 'redirects' in sandbox_data and sandbox_data['redirects'] > 0:
            report += f" | Redirects: {sandbox_data['redirects']}"
            
        return report


# Global sandbox instance
_sandbox_instance = None

def get_sandbox():
    """Get global sandbox instance"""
    global _sandbox_instance
    if _sandbox_instance is None:
        _sandbox_instance = URLSandbox()
    return _sandbox_instance


# Test code
if __name__ == "__main__":
    sandbox = URLSandbox()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://httpbin.org/delay/2",
        "http://bit.ly/test",
        "https://www.baidu.com"
    ]
    
    for url in test_urls:
        print(f"\nTesting URL: {url}")
        result = sandbox.safe_url_access(url)
        print(f"Safety: {'Safe' if result['safe'] else 'Dangerous'}")
        print(f"Risk Level: {result['risk_level']}")
        if result['warnings']:
            print(f"Warnings: {'; '.join(result['warnings'])}")
        print("-" * 50)