# C2 Mapper

Асинхронный инструмент для сбора, геолокации и визуализации Command & Control серверов из публичных threat intelligence фидов.

## Возможности

- Сбор IP из фидов abuse.ch (SSL Blacklist, Feodo Tracker, ThreatFox)
- Геолокация через DB-IP Lite — работает на территории РФ без VPN
- Автоматическое обновление базы геолокации каждые 30 дней
- Кэширование результатов в SQLite для быстрых повторных запусков
- Интерактивная карта на базе Folium с кластеризацией маркеров
- Экспорт статистики в JSON и отчёта в Markdown

## Установка

git clone https://github.com/dankertea51-cpu/C2-Mapper-THREAT-Intelligence-Geolocation-Tool.git
cd C2-Mapper-THREAT-Intelligence-Geolocation-Tool
pip install aiohttp folium geoip2 tqdm aiofiles

## Использование

python c2_map.py
python c2_map.py --debug

## Результаты

c2_output/c2_map.html
c2_output/c2_stats.json
c2_output/c2_report.md

## Примечание

База DB-IP Lite скачивается автоматически при первом запуске.

СКАЧИВАТЬ ИЗ РАЗДЕЛА RELEASES!!!!
