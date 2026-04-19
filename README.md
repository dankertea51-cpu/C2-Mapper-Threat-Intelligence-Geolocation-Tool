 C2 Mapper
Асинхронный инструмент для сбора, геолокации и визуализации Command & Control серверов из публичных threat intelligence фидов.

Возможности
Сбор IP из abuse.ch (SSL Blacklist, Feodo Tracker, ThreatFox)

Геолокация через DB-IP Lite (работает в РФ без VPN)

Автообновление базы геолокации раз в 30 дней

Кэширование в SQLite для быстрых повторных запусков

Интерактивная карта на Folium с кластеризацией

Экспорт статистики в JSON и Markdown-отчёт


Установка: git clone https://github.com/yourusername/c2-mapper.git
cd c2-mapper
pip install aiohttp folium geoip2 tqdm aiofiles


Использование: python c2_map.py  # обычный запуск
python c2_map.py --debug  # режим отладки

Результаты
В папке c2_output/ создаются:

c2_map.html — интерактивная карта

c2_stats.json — статистика

c2_report.md — текстовый отчёт

Особенности
База DB-IP Lite скачивается автоматически при первом запуске. Не требует регистрации, прокси или VPN на территории РФ.
