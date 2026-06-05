import os
import re
import base64
import ipaddress
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ГЛОБАЛЬНЫЕ НАСТРОЙКИ ---
BASE_DIR = "."
SOURCES_FILE = "sources.txt"                # Файл, откуда скрипт берёт ссылки для парсинга
OUTPUT_FILE = "YaltaVPN - Subscription"     # Итоговый файл подписки
LOG_FILE = "log.csv"                        # Файл логов
LIMIT = 100000                              # Максимальное количество строк (верхний лимит)
MAX_MB = 95                                 # Жесткий предел веса файла в мегабайтах для GitHub
IS_PUBLIC = True                            # Флаг для текста анонса (публичный/приватный)

ALLOWED_CIDRS = []     # Заполните строками подсетей (напр. '1.2.3.4/24'), если нужна фильтрация
WHITELISTED_SNI = []   # Заполните разрешенными SNI, если требуется белый список

# --- СЛОВАРНЫ И БАЗЫ ДАННЫХ ИЗ ВАШЕГО КУСКА КОДА ---
FLAG_TO_CODE = {
    "🇦🇫": "AF", "🇦🇱": "AL", "🇩🇿": "DZ", "🇦🇩": "AD", "🇦🇴": "AO",
    "🇦🇷": "AR", "🇦🇲": "AM", "🇦🇺": "AU", "🇦🇹": "AT", "🇦🇿": "AZ",
    "🇧🇩": "BD", "🇧🇾": "BY", "🇧🇪": "BE", "🇧🇷": "BR", "🇧🇬": "BG",
    "🇨🇦": "CA", "🇨🇳": "CN", "🇭🇷": "HR", "🇨🇺": "CU", "🇨🇾": "CY",
    "🇨🇿": "CZ", "🇩👑": "DK", "🇪🇬": "EG", "🇪🇪": "EE", "🇫🇮": "FI",
    "🇫🇷": "FR", "🇬🇪": "GE", "🇩🇪": "DE", "🇬🇷": "GR", "🇭🇰": "HK",
    "🇭🇺": "HU", "🇮🇸": "IS", "🇮🇳": "IN", "🇮🇩": "ID", "🇮🇷": "IR",
    "🇮🇶": "IQ", "🇮🇪": "IE", "🇮🇱": "IL", "🇮🇹": "IT", "🇯🇵": "JP",
    "🇰🇿": "KZ", "🇰🇪": "KE", "🇰🇼": "KW", "🇰🇬": "KG", "🇱🇻": "LV",
    "🇱🇧": "LB", "🇱🇾": "LY", "🇱🇹": "LT", "🇱🇺": "LU", "🇲🇾": "MY",
    "🇲🇽": "MX", "🇲🇩": "MD", "🇲🇳": "MN", "🇲🇪": "ME", "🇲🇦": "MA",
    "🇳🇱": "NL", "🇳🇿": "NZ", "🇳🇬": "NG", "🇰🇵": "KP", "🇳🇴": "NO",
    "🇵稳": "PK", "🇵🇸": "PS", "🇵🇪": "PE", "🇵🇭": "PH", "🇵🇱": "PL",
    "🇵🇹": "PT", "🇶🇦": "QA", "🇷🇴": "RO", "🇷🇺": "RU", "🇸🇦": "SA",
    "🇷🇸": "RS", "🇸🇬": "SG", "🇸🇰": "SK", "🇸🇮": "SI", "🇿🇦": "ZA",
    "🇰🇷": "KR", "🇪🇸": "ES", "🇸🇪": "SE", "🇨🇭": "CH", "🇹вань": "TW",
    "🇹🇯": "TJ", "🇹🇭": "TH", "🇹🇷": "TR", "🇹🇲": "TM", "🇺🇦": "UA",
    "🇦🇪": "AE", "🇬🇧": "GB", "🇺🇸": "US", "🇺🇾": "UY", "🇺🇿": "UZ",
    "🇻🇳": "VN",
}

COUNTRY_NAMES = {
    "россия": "RU", "russia": "RU", "russian": "RU", "ru": "RU",
    "германия": "DE", "germany": "DE", "deutschland": "DE", "de": "DE",
    "франция": "FR", "france": "FR", "fr": "FR",
    "сша": "US", "usa": "US", "united states": "US", "us": "US",
    "нидерланды": "NL", "netherlands": "NL", "holland": "NL", "nl": "NL",
    "великобритания": "GB", "uk": "GB", "united kingdom": "GB", "gb": "GB",
    "украина": "UA", "ukraine": "UA", "ua": "UA",
    "польша": "PL", "poland": "PL", "pl": "PL",
    "канада": "CA", "canada": "CA", "ca": "CA",
    "италия": "IT", "italy": "IT", "it": "IT",
    "испания": "ES", "spain": "ES", "es": "ES",
    "швеция": "SE", "sweden": "SE", "se": "SE",
    "норвегия": "NO", "norway": "NO", "no": "NO",
    "финляндия": "FI", "finland": "FI", "fi": "FI",
    "дания": "DK", "denmark": "DK", "dk": "DK",
    "швейцария": "CH", "switzerland": "CH", "ch": "CH",
    "австрия": "AT", "austria": "AT", "at": "AT",
    "бельгия": "BE", "belgium": "BE", "be": "BE",
    "япония": "JP", "japan": "JP", "jp": "JP",
    "южная корея": "KR", "south korea": "KR", "korea": "KR", "kr": "KR",
    "сингапур": "SG", "singapore": "SG", "sg": "SG",
    "индия": "IN", "india": "IN", "in": "IN",
    "бразилия": "BR", "brazil": "BR", "br": "BR",
    "турция": "TR", "turkey": "TR", "türkiye": "TR", "tr": "TR",
    "израиль": "IL", "israel": "IL", "il": "IL",
    "оаэ": "AE", "uae": "AE", "arab emirates": "AE", "ae": "AE",
    "китай": "CN", "china": "CN", "cn": "CN",
    "гонконг": "HK", "hong kong": "HK", "hk": "HK",
    "австралия": "AU", "australia": "AU", "au": "AU",
    "казахстан": "KZ", "kazakhstan": "KZ", "kz": "KZ",
    "латвия": "LV", "latvia": "LV", "lv": "LV",
    "литва": "LT", "lithuania": "LT", "lt": "LT",
    "эстония": "EE", "estonia": "EE", "ee": "EE",
    "чехия": "CZ", "czech": "CZ", "czechia": "CZ", "cz": "CZ",
    "словакия": "SK", "slovakia": "SK", "sk": "SK",
    "венгрия": "HU", "hungary": "HU", "hu": "HU",
    "румыния": "RO", "romania": "RO", "ro": "RO",
    "болгария": "BG", "bulgaria": "BG", "bg": "BG",
    "греция": "GR", "greece": "GR", "gr": "GR",
    "португалия": "PT", "portugal": "PT", "pt": "PT",
    "мексика": "MX", "mexico": "MX", "mx": "MX",
    "аргентина": "AR", "argentina": "AR", "ar": "AR",
    "чили": "CL", "chile": "CL", "cl": "CL",
    "египет": "EG", "egypt": "EG", "eg": "EG",
    "юар": "ZA", "south africa": "ZA", "za": "ZA",
    "сербия": "RS", "serbia": "RS", "rs": "RS",
    "хорватия": "HR", "croatia": "HR", "hr": "HR",
    "словения": "SI", "slovenia": "SI", "si": "SI",
    "люксембург": "LU", "luxembourg": "LU", "lu": "LU",
    "кипр": "CY", "cyprus": "CY", "cy": "CY",
    "мальта": "MT", "malta": "MT", "mt": "MT",
    "исландия": "IS", "iceland": "IS", "is": "IS",
    "монако": "MC", "monaco": "MC", "mc": "MC",
    "лихтенштейн": "LI", "liechtenstein": "LI", "li": "LI",
    "андорра": "AD", "andorra": "AD", "ad": "AD",
}

CODE_TO_RU = {
    "AF": "Афганистан", "AL": "Албания", "DZ": "Алжир", "AD": "Андорра", "AO": "Ангола",
    "AR": "Аргентина", "AM": "Армения", "AU": "Австралия", "AT": "Австрия", "AZ": "Азербайджан",
    "BD": "Бангладеш", "BY": "Беларусь", "BE": "Бельгия", "BR": "Бразилия", "BG": "Болгария",
    "CA": "Канада", "CN": "Китай", "HR": "Хорватия", "CU": "Куба", "CY": "Кипр",
    "CZ": "Чехия", "DK": "Дания", "EG": "Египет", "EE": "Эстония", "FI": "Финляндия",
    "FR": "Франция", "GE": "Грузия", "DE": "Германия", "GR": "Греция", "HK": "Гонконг",
    "HU": "Венгрия", "IS": "Исландия", "IN": "Индия", "ID": "Индонезия", "IR": "Иран",
    "IQ": "Ирак", "IE": "Ирландия", "IL": "Израиль", "IT": "Италия", "JP": "Япония",
    "KZ": "Казахстан", "KE": "Кения", "KW": "Кувейт", "KG": "Киргизия", "LV": "Латвия",
    "LB": "Ливан", "LY": "Ливия", "LT": "Литва", "LU": "Люксембург", "MY": "Малайзия",
    "MX": "Мексика", "MD": "Молдова", "MN": "Монголия", "ME": "Черногория", "MA": "Марокко",
    "NL": "Нидерланды", "NZ": "Новая Зеландия", "NG": "Нигерия", "KP": "Северная Корея", "NO": "Норвегия",
    "PK": "Пакистан", "PS": "Палестина", "PE": "Перу", "PH": "Филиппины", "PL": "Польша",
    "PT": "Португалия", "QA": "Катар", "RO": "Румыния", "RU": "Россия", "SA": "Саудовская Аравия",
    "RS": "Сербия", "SG": "Сингапур", "SK": "Словакия", "SI": "Словения", "ZA": "ЮАР",
    "KR": "Южная Корея", "ES": "Испания", "SE": "Швеция", "CH": "Швейцария", "TW": "Тайвань",
    "TJ": "Таджикистан", "TH": "Таиланд", "TR": "Турция", "TM": "Туркменистан", "UA": "Украина",
    "AE": "ОАЭ", "GB": "Великобритания", "US": "США", "UY": "Уругвай", "UZ": "Узбекистан",
    "VN": "Вьетнам",
}

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ИЗ ВАШЕГО КУСКА КОДА ---
def code_to_flag(code):
    if len(code) != 2:
        return ""
    return chr(ord(code[0]) + 0x1F1E6 - ord('A')) + chr(ord(code[1]) + 0x1F1E6 - ord('A'))

def ip_in_cidr(ip_str, cidr_str):
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False

def is_ip_allowed(ip_str):
    if not ALLOWED_CIDRS:
        return True
    return any(ip_in_cidr(ip_str, cidr) for cidr in ALLOWED_CIDRS)

def extract_sni(url, comment):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if 'sni' in qs:
        return qs['sni'][0]
    if parsed.hostname:
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            return parsed.hostname
    return ""

def is_whitelisted_sni(sni):
    if not WHITELISTED_SNI:
        return True
    return sni in WHITELISTED_SNI

def extract_ip_from_url(url):
    parsed = urlparse(url)
    host = parsed.hostname
    if host:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            return None
    return None

def extract_flag_and_country(comment):
    flag_match = re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', comment)
    if flag_match:
        flag_emoji = flag_match[0]
        if flag_emoji in FLAG_TO_CODE:
            code = FLAG_TO_CODE[flag_emoji]
            return flag_emoji, CODE_TO_RU.get(code, "🌐 Не определено")

    code_match = re.search(r'\b([A-Z]{2})\b', comment)
    if code_match:
        code = code_match.group(1).upper()
        if code in CODE_TO_RU:
            return code_to_flag(code), CODE_TO_RU[code]

    text_lower = comment.lower()
    for name, code in COUNTRY_NAMES.items():
        if name in text_lower:
            return code_to_flag(code), CODE_TO_RU.get(code, "🌐 Не определено")

    return "", "🌐 Не определено"

def parse_config_line(line):
    line = line.strip()
    if not line:
        return None

    url_part, comment = "", ""
    if '#' in line:
        url_part, comment = line.split('#', 1)
        url_part = url_part.strip()
        comment = comment.strip()
    else:
        url_part = line

    if not any(url_part.startswith(p) for p in ('vless://', 'vmess://', 'trojan://', 'ss://')):
        return None

    flag, country = extract_flag_and_country(comment + ' ' + url_part)
    sni = extract_sni(url_part, comment)
    if not is_whitelisted_sni(sni):
        return None

    ip = extract_ip_from_url(url_part)
    if ip and not is_ip_allowed(ip):
        return None

    new_name = f"{flag} {country} | SNI: {sni} | 🌴ЯлтаВПН".strip()
    return {
        "base_url": url_part,
        "new_name": new_name,
        "flag": flag,
        "country": country,
        "sni": sni,
        "ip": ip
    }

def fetch_source(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"⚠️ {url} → статус {resp.status_code}")
            return []
        
        text = resp.text
        # Добавлено: автодетекция Base64 подписок (если контент зашифрован)
        try:
            clean_text = text.strip().replace('\r', '').replace('\n', '').replace(' ', '')
            padded_text = clean_text + '=' * (-len(clean_text) % 4)
            decoded_bytes = base64.b64decode(padded_text, validate=True)
            text = decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            pass

        configs = []
        for line in text.splitlines():
            parsed = parse_config_line(line)
            if parsed:
                configs.append(parsed)
        return configs
    except Exception as e:
        print(f"❌ Ошибка {url}: {e}")
        return []

def save_to_drive(content, filename):
    path = os.path.join(BASE_DIR, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def log_to_sheet(total, cidr_count, unique_sni):
    path = os.path.join(BASE_DIR, LOG_FILE)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    needed_header = not os.path.exists(path)
    
    # Считываем старые логи, чтобы держать размер log.csv в рамках приличия (макс 1000 строк)
    log_lines = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            log_lines = f.readlines()
            
    new_entry = f"{now},{total},{cidr_count},{unique_sni}\n"
    if needed_header:
        log_lines.append("timestamp,total,cidr_count,unique_sni\n")
    log_lines.append(new_entry)
    
    # Ограничиваем историю логов тысячестрочным лимитом
    log_lines = log_lines[-1000:]
    
    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(log_lines)

def load_sources_from_file(file_path):
    """Динамически загружает ссылки из файла sources.txt"""
    if not os.path.exists(file_path):
        # Если файла нет, возвращаем пустой список (или пропишите дефолтные ссылки сюда)
        return []
    urls = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    return list(set(urls))

# --- ОСНОВНАЯ ЛОГИКА MAIN ---
def main():
    # Загружаем список источников из внешнего файла sources.txt
    sources = load_sources_from_file(SOURCES_FILE)
    if not sources:
        print(f"❌ Файл {SOURCES_FILE} пуст или отсутствует. Нечего парсить.")
        return

    all_configs = []
    url_set = set()

    print(f"🌴 ЯлтаВПН - Курортный ВПН | лимит строк: {LIMIT} | источников: {len(sources)}")
    print("📡 Начало параллельной загрузки источников...")

    # Пул потоков для быстрого скачивания сайтов
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in sources}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                configs = future.result()
                for cfg in configs:
                    if cfg['base_url'] not in url_set:
                        url_set.add(cfg['base_url'])
                        all_configs.append(cfg)
            except Exception as e:
                print(f"❌ Ошибка обработки пула для {url}: {e}")

    # Применяем первичный лимит на число строк из настроек
    all_configs = all_configs[:LIMIT]

    # Подсчет метрик
    now = datetime.now()
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
    cidr_count = sum(1 for c in all_configs if c['ip'] and is_ip_allowed(c['ip']))
    unique_sni = len({c['sni'] for c in all_configs})

    # Формирование строки анонса (исправленные многострочники)
    if IS_PUBLIC:
        announce = (f"🌴 ЯлтаВПН - Курортный ВПН | 💊 Расширенная подписка | "
                    f"конфигов: {len(all_configs)} (CIDR: {cidr_count}) | SNI: {unique_sni} | "
                    f"обновлено: {timestamp}")
    else:
        announce = (f"🌴 ЯлтаВПН - Курортный ВПН 🔒PRIVATE | 💊 Расширенная подписка | "
                    f"конфигов: {len(all_configs)} (CIDR: {cidr_count}) | SNI: {unique_sni} | "
                    f"обновлено: {timestamp}")
    print(f"\n📢 {announce}")

    # --- ИНТЕГРАЦИЯ ЖЕСТКОГО ТЕКСТОВОГО ЛИМИТА В 95 МБ ---
    max_bytes = MAX_MB * 1024 * 1024
    current_size_bytes = 0
    lines_to_save = []

    # Строим итоговые строки конфигураций с новыми именами
    for cfg in all_configs:
        # Склеиваем чистый конфиг-URL и красивое имя ЯлтаВПН через знак решетки
        final_line = f"{cfg['base_url']}#{cfg['new_name']}\n"
        line_size = len(final_line.encode('utf-8'))

        # Контролируем, чтобы общий размер текста строго не превысил 95 МБ
        if current_size_bytes + line_size > max_bytes:
            print(f"\n⚠️ Предупреждение: Обнаружено превышение лимита в {MAX_MB} МБ.")
            print(f"Запись остановлена на {len(lines_to_save)} строках.")
            break

        lines_to_save.append(final_line)
        current_size_bytes += line_size

    # Склеиваем всё в единую текстовую строку контента
    final_content = "".join(lines_to_save)

    # Сохраняем итоговый plain-text файл подписки
    save_to_drive(final_content, OUTPUT_FILE)
    print(f"✅ Файл подписки '{OUTPUT_FILE}' успешно перезаписан.")
    print(f"📦 Итоговый размер на диске: {os.path.getsize(os.path.join(BASE_DIR, OUTPUT_FILE)) / (1024*1024):.2f} МБ")

    # Пишем данные в лог-таблицу
    log_to_sheet(len(lines_to_save), cidr_count, unique_sni)
    print("📈 Логи успешно обновлены.")

if __name__ == "__main__":
    main()
