# smtp

smtp_client.py - доработанная версия с обработкой ошибок
Обрабатываются:
- сетевые ошибки (разрыв соединения, таймаут, ...)
- ошибки SMTP (ошибка авторизации; коды ответов, не соответствующие ожидаемым на используемые команды)
- ошибки парсинга конфигурационных файлов и отсутствия указанных файлов в них

smtp_client_old.py - соответственно старая версия без обработки ошибок
