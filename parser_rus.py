import os
import re
import base64
import gzip
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ ---
SOURCES_FILE = "sources.txt"               # Файл с вашими ссылками-источниками
OUTPUT_FILE = "YaltaVPN - Subscription.gz"  # Итоговый сжатый файл подписки (добавлен .gz)
MAX_MB = 95                                 # Жесткий лимит размера готового АРХИВА (в МБ)
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

def save_with_gzip_compression(file_path, proxies_list, max_mb):
    """
    Фильтрует дубликаты, сжимает данные в формат GZIP 
    и контролирует, чтобы получившийся архив не превышал max_mb.
    """
    # 1. Очистка от дубликатов
    seen = set()
    unique_proxies = []
    for p in proxies_list:
        clean = p.strip()
        if clean and clean not in seen:
            seen.add(clean)
            unique_proxies.append(clean)
            
    max_bytes = max_mb * 1024 * 1024
    
    # Внутренняя функция для записи данных в GZIP
    def write_gzip(proxies_to_write):
        with gzip.open(file_path, "wt", encoding="utf-8") as f:
            for proxy in proxies_to_write:
                f.write(f"{proxy}\n")
        return os.path.getsize(file_path)

    # 2. Первичная попытка сжать абсолютно все найденные уникальные конфиги
    current_archive_size = write_gzip(unique_proxies)
    
    # 3. Если сжатый (!) файл всё равно больше 95 МБ (это миллионы прокси),
    # пропорционально обрезаем список и пересохраняем.
    if current_archive_size > max_bytes:
        print(f"\n⚠️ Даже в сжатом виде архив ({current_archive_size / (1024*1024):.2f} МБ) превышает лимит {max_mb} МБ!")
        print("Запущена процедура безопасного отсечения лишних данных...")
        
        while current_archive_size > max_bytes and len(unique_proxies) > 0:
            # Рассчитываем коэффициент превышения и уменьшаем размер списка прокси
            reduction_factor = max_bytes / current_archive_size
            new_count = int(len(unique_proxies) * reduction_factor * 0.95) # 5% запас
            
            unique_proxies = unique_proxies[:new_count]
            current_archive_size = write_gzip(unique_proxies)
            
        print(f"Отрезано лишнее. Новое количество конфигов в архиве: {len(unique_proxies)}")

    # Выводим финальную статистику
    print(f"\n✅ Подписка успешно СЖАТА и сохранена: '{file_path}'")
    print(f"📦 Размер GZIP-архива на диске: {current_archive_size / (1024 * 1024):.2f} МБ")
    print(f"🔢 Упаковано уникальных конфигов: {len(unique_proxies)}")

def main():
    print("🚀 Запуск многопоточного парсера YaltaVPN с GZIP-сжатием...")
    
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
    
    # 3. Сохранение с реальным GZIP-сжатием и лимитом в 95 МБ
    save_with_gzip_compression(OUTPUT_FILE, all_collected_proxies, MAX_MB)

if __name__ == "__main__":
    main()
