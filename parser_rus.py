import os
import re
import csv
import sys
import base64
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = 'sources.txt'
OUTPUT_FILE = 'YaltaVPN - Subscription'
LOG_FILE = 'log.csv'

def extract_urls(file_path):
    urls = []
    if not os.path.exists(file_path):
        print(f"❌ КРИТИЧЕСКАЯ ОШИБКА: Файл '{file_path}' не найден в репозитории!", flush=True)
        sys.exit(1)

    url_pattern = re.compile(r'https?://[^\s"\'><]+')
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for url in url_pattern.findall(line):
                cleaned_url = url.strip('.,;()[]{}~# \r\n\t')
                if cleaned_url:
                    urls.append(cleaned_url)
    return list(set(urls))

def filter_vpn_sources(urls):
    vpn_keywords = ['sub', '.txt', '.yaml', '.yml', '.json', 'gist', 'githubusercontent', 'gitverse', 'vless', 'vmess', 'whitelist', 'blacklist', 'free', 'proxy']
    exclude_keywords = ['/releases', '/articles', 'habr.com', 'hightech.fm', 'music.yandex', 'arxiv.org', 'funpay.com', 'tiktok.com', '3dnews.ru', '9to5mac.com', 'blog.google']
    
    filtered = []
    for url in urls:
        url_lower = url.lower()
        if any(kw in url_lower for kw in vpn_keywords):
            if not any(ex in url_lower for ex in exclude_keywords):
                filtered.append(url)
    return filtered

def try_decode_base64(text):
    cleaned = text.strip()
    if not cleaned:
        return text
    try:
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        decoded_bytes = base64.b64decode(padded)
        decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
        if any(proto in decoded_text for proto in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hy2://', 'hysteria2://']):
            return decoded_text
    except Exception:
        pass
    return text

def fetch_url(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return url, response.text, "Success"
        return url, None, f"HTTP_{response.status_code}"
    except Exception as e:
        return url, None, f"Error_{type(e).__name__}"

def main():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"⏳ [{timestamp}] Старт парсера parser_rus.py в GitHub Actions...", flush=True)

    all_urls = extract_urls(INPUT_FILE)
    target_urls = filter_vpn_sources(all_urls)
    print(f"📋 Всего ссылок: {len(all_urls)} | К проверке: {len(target_urls)}", flush=True)

    collected_nodes = set()
    log_rows = []
    
    node_pattern = re.compile(r'(?:vless|vmess|ss|trojan|hysteria2|hy2|shadowsocks)://[^\s"\'><,;]+')

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(fetch_url, url): url for url in target_urls}
        
        for future in as_completed(futures):
            url, raw_content, status = future.result()
            nodes_count = 0
            
            if raw_content:
                processed_content = try_decode_base64(raw_content)
                nodes = node_pattern.findall(processed_content)
                for node in nodes:
                    cleaned_node = node.strip(' \r\n\t,;')
                    if cleaned_node:
                        collected_nodes.add(cleaned_node)
                nodes_count = len(nodes)
            
            log_rows.append([timestamp, url, status, nodes_count])
            print(f"   [{status}] Найдено нод: {nodes_count} -> {url}", flush=True)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
        for node in sorted(collected_nodes):
            out_f.write(node + '\n')
    print(f"✅ Файл подписки '{OUTPUT_FILE}' обновлен. Уникальных нод: {len(collected_nodes)}", flush=True)

    log_exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as csv_f:
        writer = csv.writer(csv_f)
        if not log_exists:
            writer.writerow(['Timestamp', 'URL', 'Status', 'NodesFound'])
        writer.writerows(log_rows)
    print(f"📊 Лог '{LOG_FILE}' сохранен.", flush=True)

if __name__ == '__main__':
    main()
