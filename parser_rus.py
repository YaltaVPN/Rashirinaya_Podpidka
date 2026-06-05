import os
import re
import base64
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ ---
SOURCES_FILE = "sources.txt"               # Файл с вашими ссылками-источниками
OUTPUT_FILE = "YaltaVPN - Subscription"     # Итоговый текстовый файл подписки
MAX_MB = 95                                 # Жесткий лимит размера текстового файла (в МБ)
MAX_WORKERS = 20                            # Количество одновременных потоков скачивания
TIMEOUT = 10                                # Таймаут ожидания ответа от сайтов (в секундах)

# Регулярное выражение для поиска всех типов прокси-конфигов
PROXY_REGEX = re.compile(r'(?:vless|vmess|ss|trojan|tuic|hysteria2|hy2)://[^\s"\'`,<>\]\}]+')

def load_sources(file_path):
    """Читает источники из файла sources.txt и очищает их."""
    urls = []
    if not os.path.exists(file_path):
        print(f"❌ Файл с источниками '{file_path}' не найден!")
        return urls
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Извлекаем чистый URL (убираем префиксы и хвосты)
            match = re.search(r'https?://[^\s]+', line)
            if match:
                url = match.group(0).rstrip('~').rstrip(',').rstrip(';')
                urls.append(url)
                
    seen = set()
    return [x for x in urls if not (x in seen or seen.add(x))]

def fetch_source(url):
    """Скачивает один источник и извлекает из него прокси-конфиги."""
    proxies = []
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        )
        
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            html_bytes = response.read()
            text = html_bytes.decode('utf-8', errors='ignore')
            
            # Автодетекция сплошного Base64 подписок
            try:
                clean_text = text.strip().replace('\r', '').replace('\n', '').replace(' ', '')
                padded_text = clean_text + '=' * (-len(clean_text) % 4)
                decoded_bytes = base64.b64decode(padded_text, validate=True)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                
                if any(proto in decoded_text for proto in ['vless://', 'vmess://', 'ss://', 'trojan://']):
                    text = decoded_text
            except Exception:
                pass
            
            found = PROXY_REGEX.findall(text)
            return found
    except Exception:
        pass  # Игнорируем ошибки недоступных сайтов
    return proxies

def save_with_strict_limit(file_path, proxies_list, max_mb):
    """
    Фильтрует дубликаты, склеивает конфиги в чистый текст 
    и контролирует, чтобы итоговый текстовый файл строго не превышал max_mb.
    """
    # 1. Очистка от дубликатов с сохранением порядка
    seen = set()
    unique_proxies = []
    for p in proxies_list:
        clean = p.strip()
        if clean and clean not in seen:
            seen.add(clean)
            unique_proxies.append(clean)
            
    max_bytes = max_mb * 1024 * 1024
    current_size_bytes = 0
    safe_proxies = []
    
    # 2. Построчно считаем точный физический вес текста в байтах (UTF-8)
    for proxy in unique_proxies:
        line = f"{proxy}\n"
        line_size = len(line.encode('utf-8'))
        
        # Если добавление этой строки пробьет лимит в 95 МБ — останавливаем сбор
        if current_size_bytes + line_size > max_bytes:
            print(f"\n⚠️ Достигнут жесткий лимит размера текстового файла ({max_mb} МБ)!")
            print(f"Сбор остановлен. Сохранено {len(safe_proxies)} из {len(unique_proxies)} доступных конфигов.")
            break
            
        safe_proxies.append(line)
        current_size_bytes += line_size

    # 3. Полностью перезаписываем файл (режим 'w', чистый некодированный текст)
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(safe_proxies)
        
    final_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"\n✅ Подписка успешно обновлена: '{file_path}'")
    print(f"📦 Размер текстового файла на диске: {final_size_mb:.2f} МБ")
    print(f"🔢 Всего уникальных конфигов сохранено: {len(safe_proxies)}")

def main():
    print("🚀 Запуск многопоточного парсера YaltaVPN (Текстовый лимит 95 МБ)...")
    
    # 1. Загрузка ссылок
    urls = load_sources(SOURCES_FILE)
    print(f"📋 Из '{SOURCES_FILE}' загружено уникальных источников: {len(urls)}")
    if not urls:
        print("📭 Список источников пуст. Завершение работы.")
        return
        
    all_collected_proxies = []
    
    # 2. Многопоточный сбор
    print(f"🌐 Опрашиваем сайты в {MAX_WORKERS} потоков...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in urls}
        
        completed = 0
        for future in as_completed(future_to_url):
            completed += 1
            try:
                result = future.result()
                if result:
                    all_collected_proxies.extend(result)
            except Exception:
                pass
            
            if completed % 10 == 0 or completed == len(urls):
                print(f"⏳ Обработано сайтов: {completed}/{len(urls)}...", end='\r')
                
    print(f"\n✨ Сбор завершен. Найдено сырых записей: {len(all_collected_proxies)}")
    
    # 3. Сохранение в чистый текст с лимитом
    save_with_strict_limit(OUTPUT_FILE, all_collected_proxies, MAX_MB)

if __name__ == "__main__":
    main()
