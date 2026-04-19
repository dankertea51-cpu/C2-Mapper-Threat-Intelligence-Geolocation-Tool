#!/usr/bin/env python3
"""
C2 Server Interactive Map Generator
Парсит публичные источники C2-серверов и строит интерактивную карту
Использует DB-IP Lite для геолокации (работает в России)
"""

import asyncio
import aiohttp
import aiofiles
import sqlite3
import json
import re
import gzip
import shutil
import sys
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import Counter
import folium
from folium.plugins import MarkerCluster
from tqdm.asyncio import tqdm
import geoip2.database
import geoip2.errors

# Режим отладки (из аргументов командной строки)
DEBUG_MODE = '--debug' in sys.argv

# Константы
SOURCES = [
    {
        'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
        'type': 'text',
        'name': 'SSL Blacklist (abuse.ch)'
    },
    {
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'type': 'text',
        'name': 'Feodo Tracker (abuse.ch)'
    },
    {
        'url': 'https://threatfox.abuse.ch/export/json/ip-port/recent/',
        'type': 'json',
        'name': 'ThreatFox IOC (abuse.ch)'
    },
]

OUTPUT_DIR = Path("c2_output")
CACHE_DB = OUTPUT_DIR / "geo_cache.db"
DBIP_DB = "dbip-city-lite.mmdb"
DBIP_URL = "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz"
DBIP_MAX_AGE_DAYS = 30

# Регулярные выражения
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
PORT_PATTERN = re.compile(r':(\d+)')
CIDR_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}\b')


async def download_dbip() -> bool:
    """
    Скачивание и распаковка DB-IP Lite базы
    Возвращает True если база готова к использованию
    """
    db_path = Path(DBIP_DB)

    # Проверка существующей базы
    if db_path.exists():
        file_age = datetime.now() - datetime.fromtimestamp(db_path.stat().st_mtime)
        if file_age.days < DBIP_MAX_AGE_DAYS:
            file_size = db_path.stat().st_size / (1024 * 1024)
            file_date = datetime.fromtimestamp(db_path.stat().st_mtime).strftime('%Y-%m-%d')
            print(f"✅ DB-IP база найдена: {file_size:.1f} MB, обновлена {file_date}")

            # Проверка целостности
            try:
                with geoip2.database.Reader(str(db_path)) as reader:
                    reader.city('8.8.8.8')  # Тестовый запрос
                return True
            except Exception as e:
                print(f"⚠️  База повреждена: {e}, скачиваю заново...")
                db_path.unlink()
        else:
            print(f"⚠️  База устарела ({file_age.days} дней), скачиваю новую...")
            db_path.unlink()

    # Скачивание новой базы
    print(f"📥 Скачивание DB-IP Lite с {DBIP_URL}...")
    gz_path = Path(f"{DBIP_DB}.gz")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(DBIP_URL, timeout=aiohttp.ClientTimeout(total=300)) as response:
                if response.status != 200:
                    print(f"❌ Ошибка загрузки: HTTP {response.status}")
                    return False

                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0

                async with aiofiles.open(gz_path, 'wb') as f:
                    async for chunk in response.content.iter_chunked(8192):
                        await f.write(chunk)
                        downloaded += len(chunk)
                        if total_size:
                            progress = (downloaded / total_size) * 100
                            print(f"\r📥 Загрузка: {progress:.1f}% ({downloaded / (1024*1024):.1f} MB)", end='')

                print()  # Новая строка после прогресса

        # Распаковка gzip
        print("📦 Распаковка базы...")
        with gzip.open(gz_path, 'rb') as f_in:
            with open(db_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Удаление архива
        gz_path.unlink()

        # Проверка целостности
        file_size = db_path.stat().st_size / (1024 * 1024)
        print(f"✅ DB-IP база установлена: {file_size:.1f} MB")

        try:
            with geoip2.database.Reader(str(db_path)) as reader:
                test = reader.city('8.8.8.8')
                print(f"✅ Проверка целостности: OK (тест: {test.country.name})")
            return True
        except Exception as e:
            print(f"❌ База повреждена после загрузки: {e}")
            db_path.unlink()
            return False

    except Exception as e:
        print(f"❌ Ошибка загрузки DB-IP: {e}")
        if gz_path.exists():
            gz_path.unlink()
        return False


class GeoCache:
    """Кэш геолокации в SQLite"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Инициализация БД"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS geo_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    city TEXT,
                    lat REAL,
                    lon REAL,
                    asn INTEGER,
                    as_org TEXT,
                    timestamp INTEGER
                )
            """)
            conn.commit()

    def get(self, ip: str) -> Optional[Dict]:
        """Получить данные из кэша"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT country, city, lat, lon, asn, as_org FROM geo_cache WHERE ip = ?",
                (ip,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'country': row[0],
                    'city': row[1],
                    'lat': row[2],
                    'lon': row[3],
                    'asn': row[4],
                    'as_org': row[5]
                }
        return None

    def set(self, ip: str, data: Dict):
        """Сохранить данные в кэш"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO geo_cache
                (ip, country, city, lat, lon, asn, as_org, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                data.get('country'),
                data.get('city'),
                data.get('lat'),
                data.get('lon'),
                data.get('asn'),
                data.get('as_org'),
                int(datetime.now().timestamp())
            ))
            conn.commit()


class C2Collector:
    """Сборщик данных о C2-серверах"""

    def __init__(self):
        self.geo_cache = GeoCache(CACHE_DB)
        self.geoip_reader = None
        self.fallback_count = 0

        # Инициализация DB-IP
        try:
            if Path(DBIP_DB).exists():
                self.geoip_reader = geoip2.database.Reader(DBIP_DB)
                print("✅ DB-IP база загружена")
            else:
                print("⚠️  DB-IP база не найдена, будет использован fallback на IP-API.com")
        except Exception as e:
            print(f"⚠️  Ошибка загрузки DB-IP: {e}")
            print("⚠️  Будет использован fallback на IP-API.com")

    async def fetch_url(self, session: aiohttp.ClientSession, url: str, retries: int = 3) -> str:
        """Асинхронная загрузка URL с retry и User-Agent"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        for attempt in range(retries):
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        content = await response.text()
                        if DEBUG_MODE:
                            print(f"✅ [{url.split('/')[-1]}] Загружено {len(content)} байт")
                        return content
                    else:
                        if DEBUG_MODE:
                            print(f"⚠️  [{url.split('/')[-1]}] HTTP {response.status} (попытка {attempt + 1}/{retries})")
            except asyncio.TimeoutError:
                if DEBUG_MODE:
                    print(f"⏱️  [{url.split('/')[-1]}] Таймаут (попытка {attempt + 1}/{retries})")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"❌ [{url.split('/')[-1]}] Ошибка: {e} (попытка {attempt + 1}/{retries})")

            # Задержка перед повторной попыткой
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)  # Экспоненциальная задержка: 1s, 2s, 4s

        print(f"❌ Не удалось загрузить {url} после {retries} попыток")
        return ""

    def extract_ips(self, text: str, source_name: str, source_type: str = 'text') -> List[Tuple[str, List[int]]]:
        """Извлечение IP-адресов и портов (поддержка text и JSON)"""
        ips = []

        # Парсинг JSON (ThreatFox)
        if source_type == 'json':
            try:
                data = json.loads(text)
                if isinstance(data, dict) and 'data' in data:
                    for entry in data['data']:
                        ioc_value = entry.get('ioc_value', '')

                        # Формат: IP:port или просто IP
                        if ':' in ioc_value:
                            parts = ioc_value.split(':')
                            if len(parts) == 2 and IP_PATTERN.match(parts[0]):
                                ip = parts[0]
                                try:
                                    port = int(parts[1])
                                    # Валидация IP
                                    ip_obj = ipaddress.ip_address(ip)
                                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                                        ips.append((ip, [port]))
                                        if DEBUG_MODE:
                                            threat_type = entry.get('threat_type', 'unknown')
                                            print(f"  [JSON] {ip}:{port} ({threat_type})")
                                except (ValueError, ipaddress.AddressValueError):
                                    continue
                        else:
                            # Одиночный IP
                            ip_match = IP_PATTERN.match(ioc_value)
                            if ip_match:
                                ip = ip_match.group()
                                try:
                                    ip_obj = ipaddress.ip_address(ip)
                                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                                        ips.append((ip, [443]))
                                except (ValueError, ipaddress.AddressValueError):
                                    continue

                if DEBUG_MODE:
                    print(f"📊 [{source_name}] Найдено IP из JSON: {len(ips)}")
                return ips

            except json.JSONDecodeError as e:
                if DEBUG_MODE:
                    print(f"❌ [{source_name}] Ошибка парсинга JSON: {e}")
                return []

        # Парсинг текстовых источников
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue

            # Пропуск доменов (содержат буквы)
            if re.search(r'[a-zA-Z]', line.split(':')[0].split('/')[0]):
                continue

            # 1. Проверка CIDR (например, 192.168.0.0/16)
            cidr_match = CIDR_PATTERN.search(line)
            if cidr_match:
                try:
                    network = ipaddress.ip_network(cidr_match.group(), strict=False)
                    # Берём первый IP из подсети как представитель
                    representative_ip = str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address)

                    # Поиск портов в строке
                    ports = [int(p) for p in PORT_PATTERN.findall(line)]
                    ips.append((representative_ip, ports if ports else [443]))

                    if DEBUG_MODE:
                        print(f"  [CIDR] {cidr_match.group()} → {representative_ip}")
                    continue
                except (ValueError, ipaddress.AddressValueError):
                    pass  # Невалидный CIDR

            # 2. Проверка IP:port (например, 192.168.1.1:443)
            if ':' in line:
                parts = line.split(':')
                if len(parts) == 2 and IP_PATTERN.match(parts[0]):
                    ip = parts[0]
                    try:
                        port = int(parts[1].split()[0])  # Берём только число
                        # Валидация IP
                        ip_obj = ipaddress.ip_address(ip)
                        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                            ips.append((ip, [port]))
                            continue
                    except (ValueError, ipaddress.AddressValueError):
                        pass

            # 3. Одиночный IP (например, 192.168.1.1)
            ip_match = IP_PATTERN.search(line)
            if ip_match:
                ip = ip_match.group()

                # Валидация IP (исключаем 0.0.0.0, 255.255.255.255, локальные)
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                        continue
                except (ValueError, ipaddress.AddressValueError):
                    continue

                # Поиск портов в строке
                ports = [int(p) for p in PORT_PATTERN.findall(line)]
                ips.append((ip, ports if ports else [443]))

        if DEBUG_MODE:
            print(f"📊 [{source_name}] Найдено IP: {len(ips)}")

        return ips

    async def get_geolocation_fallback(self, ip: str) -> Optional[Dict]:
        """Fallback геолокация через IP-API.com (бесплатный API)"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,as,isp"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success':
                            result = {
                                'country': data.get('country', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'lat': data.get('lat'),
                                'lon': data.get('lon'),
                                'asn': None,
                                'as_org': data.get('isp', 'Unknown')
                            }
                            # Извлечение ASN из поля 'as'
                            if data.get('as'):
                                asn_match = re.search(r'AS(\d+)', data['as'])
                                if asn_match:
                                    result['asn'] = int(asn_match.group(1))
                            return result
        except Exception as e:
            print(f"⚠️  Fallback ошибка для {ip}: {e}")
        return None

    async def get_geolocation(self, ip: str) -> Optional[Dict]:
        """Получение геолокации IP (DB-IP + fallback на IP-API)"""
        # Проверка кэша
        cached = self.geo_cache.get(ip)
        if cached:
            return cached

        data = None

        # Попытка через DB-IP
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)

                data = {
                    'country': response.country.name or 'Unknown',
                    'city': response.city.name or 'Unknown',
                    'lat': response.location.latitude,
                    'lon': response.location.longitude,
                    'asn': None,
                    'as_org': 'Unknown'
                }

            except geoip2.errors.AddressNotFoundError:
                pass  # IP не найден в базе
            except Exception as e:
                print(f"⚠️  DB-IP ошибка для {ip}: {e}")

        # Fallback на IP-API.com
        if not data:
            self.fallback_count += 1
            data = await self.get_geolocation_fallback(ip)
            if data:
                await asyncio.sleep(0.3)  # Rate limit: ~3 req/sec для IP-API

        # Сохранение в кэш
        if data:
            self.geo_cache.set(ip, data)
            return data

        return None

    async def collect_c2_data(self) -> List[Dict]:
        """Сбор всех данных о C2-серверах"""
        all_ips = {}

        async with aiohttp.ClientSession() as session:
            print("📡 Загрузка источников...")
            tasks = [self.fetch_url(session, source['url']) for source in SOURCES]

            results = []
            for task in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Загрузка"):
                results.append(await task)

            # Парсинг IP
            print("\n🔍 Извлечение IP-адресов...")
            if DEBUG_MODE:
                print("\n=== РЕЖИМ ОТЛАДКИ ===")

            for source, content in zip(SOURCES, results):
                if not content:
                    if DEBUG_MODE:
                        print(f"❌ [{source['name']}] Пустой ответ")
                    continue

                ips = self.extract_ips(content, source['name'], source['type'])
                for ip, ports in ips:
                    if ip not in all_ips:
                        all_ips[ip] = {'ports': set(), 'sources': []}
                    all_ips[ip]['ports'].update(ports)
                    all_ips[ip]['sources'].append(source['name'])

            if DEBUG_MODE:
                print(f"\n📊 ИТОГО уникальных IP: {len(all_ips)}")
                print("=" * 40 + "\n")

        # Геолокация
        print(f"\n🌍 Определение геолокации для {len(all_ips)} IP...")
        c2_data = []

        for ip, info in tqdm(all_ips.items(), desc="Геолокация"):
            geo = await self.get_geolocation(ip)
            if geo and geo['lat'] and geo['lon']:
                c2_data.append({
                    'ip': ip,
                    'ports': sorted(list(info['ports'])),
                    'sources': info['sources'],
                    **geo
                })

        if self.fallback_count > 0:
            print(f"ℹ️  Использован fallback (IP-API.com) для {self.fallback_count} IP")

        return c2_data

    def __del__(self):
        """Закрытие GeoIP ридеров"""
        if self.geoip_reader:
            self.geoip_reader.close()


class C2Visualizer:
    """Визуализация C2-серверов на карте"""

    def __init__(self, c2_data: List[Dict]):
        self.c2_data = c2_data

    def generate_map(self) -> folium.Map:
        """Создание интерактивной карты"""
        # Центр карты (средние координаты)
        avg_lat = sum(d['lat'] for d in self.c2_data) / len(self.c2_data)
        avg_lon = sum(d['lon'] for d in self.c2_data) / len(self.c2_data)

        # Создание карты
        m = folium.Map(
            location=[avg_lat, avg_lon],
            zoom_start=2,
            tiles='OpenStreetMap'
        )

        # Кластеризация маркеров
        marker_cluster = MarkerCluster().add_to(m)

        # Добавление маркеров
        for c2 in self.c2_data:
            # Цвет маркера (по количеству портов)
            if len(c2['ports']) > 3:
                color = 'red'  # Активные
            elif len(c2['ports']) > 1:
                color = 'orange'  # Средние
            else:
                color = 'green'  # Новые/одиночные

            # Popup с информацией
            popup_html = f"""
            <div style="font-family: monospace; min-width: 200px;">
                <h4 style="margin: 0 0 10px 0;">🎯 C2 Server</h4>
                <b>IP:</b> {c2['ip']}<br>
                <b>Country:</b> {c2['country']}<br>
                <b>City:</b> {c2['city']}<br>
                <b>Ports:</b> {', '.join(map(str, c2['ports']))}<br>
                <b>AS:</b> {c2['as_org']}<br>
                <b>Sources:</b> {', '.join(c2['sources'])}
            </div>
            """

            folium.Marker(
                location=[c2['lat'], c2['lon']],
                popup=folium.Popup(popup_html, max_width=300),
                tooltip=f"{c2['ip']} ({c2['country']})",
                icon=folium.Icon(color=color, icon='info-sign')
            ).add_to(marker_cluster)

        return m

    def generate_statistics(self) -> Dict:
        """Генерация статистики"""
        stats = {
            'total_servers': len(self.c2_data),
            'total_ports': sum(len(c2['ports']) for c2 in self.c2_data),
            'top_countries': Counter(c2['country'] for c2 in self.c2_data).most_common(10),
            'top_as': Counter(c2['as_org'] for c2 in self.c2_data if c2['as_org'] != 'Unknown').most_common(5),
            'port_distribution': Counter(port for c2 in self.c2_data for port in c2['ports']),
            'timestamp': datetime.now().isoformat()
        }
        return stats

    def generate_report(self, stats: Dict) -> str:
        """Генерация Markdown-отчёта"""
        report = f"""# C2 Server Analysis Report

**Generated:** {stats['timestamp']}

## 📊 Summary

- **Total C2 Servers:** {stats['total_servers']}
- **Total Ports:** {stats['total_ports']}
- **Average Ports per Server:** {stats['total_ports'] / stats['total_servers']:.2f}

## 🌍 Top 10 Countries

| Rank | Country | Count |
|------|---------|-------|
"""
        for i, (country, count) in enumerate(stats['top_countries'], 1):
            report += f"| {i} | {country} | {count} |\n"

        report += "\n## 🏢 Top 5 Autonomous Systems\n\n"
        report += "| Rank | AS Organization | Count |\n"
        report += "|------|-----------------|-------|\n"

        for i, (as_org, count) in enumerate(stats['top_as'], 1):
            report += f"| {i} | {as_org} | {count} |\n"

        report += "\n## 🔌 Port Distribution\n\n"
        report += "| Port | Count |\n"
        report += "|------|-------|\n"

        for port, count in sorted(stats['port_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]:
            report += f"| {port} | {count} |\n"

        report += "\n## 🔍 Key Findings\n\n"

        # Автоматические выводы
        top_country = stats['top_countries'][0][0] if stats['top_countries'] else 'Unknown'
        top_as = stats['top_as'][0][0] if stats['top_as'] else 'Unknown'

        report += f"1. **Geographic Concentration:** {top_country} hosts the most C2 servers ({stats['top_countries'][0][1]} servers)\n"
        report += f"2. **Infrastructure Provider:** {top_as} is the most common hosting provider\n"
        report += f"3. **Port Usage:** Port {max(stats['port_distribution'], key=stats['port_distribution'].get)} is most frequently used\n"

        return report


async def main():
    """Главная функция"""
    print("🚀 C2 Server Map Generator (DB-IP Edition)\n")

    if DEBUG_MODE:
        print("🐛 РЕЖИМ ОТЛАДКИ ВКЛЮЧЁН\n")

    # Создание директории вывода
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Скачивание/проверка DB-IP базы
    if not await download_dbip():
        print("⚠️  DB-IP база недоступна, будет использован только fallback (IP-API.com)")
        print("⚠️  Это может быть медленнее из-за rate limits\n")

    # Сбор данных
    collector = C2Collector()
    c2_data = await collector.collect_c2_data()

    if not c2_data:
        print("❌ Не удалось собрать данные о C2-серверах")
        print("\n💡 Попробуйте:")
        print("   1. Проверить интернет-соединение")
        print("   2. Запустить с флагом --debug для диагностики")
        print("   3. Проверить доступность источников вручную")
        return

    print(f"\n✅ Собрано {len(c2_data)} C2-серверов с геолокацией")

    # Визуализация
    print("\n🗺️  Создание карты...")
    visualizer = C2Visualizer(c2_data)

    # Карта
    c2_map = visualizer.generate_map()
    map_path = OUTPUT_DIR / "c2_map.html"
    c2_map.save(str(map_path))
    print(f"✅ Карта сохранена: {map_path}")

    # Статистика
    print("\n📈 Генерация статистики...")
    stats = visualizer.generate_statistics()
    stats_path = OUTPUT_DIR / "c2_stats.json"
    async with aiofiles.open(stats_path, 'w', encoding='utf-8') as f:
        await f.write(json.dumps(stats, indent=2, ensure_ascii=False))
    print(f"✅ Статистика сохранена: {stats_path}")

    # Отчёт
    print("\n📝 Генерация отчёта...")
    report = visualizer.generate_report(stats)
    report_path = OUTPUT_DIR / "c2_report.md"
    async with aiofiles.open(report_path, 'w', encoding='utf-8') as f:
        await f.write(report)
    print(f"✅ Отчёт сохранён: {report_path}")

    print(f"\n🎉 Готово! Откройте {map_path} в браузере")
    print(f"\n💡 Для отладки запустите: python c2_map.py --debug")


if __name__ == "__main__":
    asyncio.run(main())
