from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    "app_title": {"ru": "RouterWatch — монитор трафика роутера", "en": "RouterWatch — router traffic monitor"},
    "choose_language": {"ru": "Выберите язык / Choose language", "en": "Choose language / Выберите язык"},
    "lang_ru": {"ru": "Русский", "en": "Русский"},
    "lang_en": {"ru": "English", "en": "English"},
    "continue": {"ru": "Продолжить", "en": "Continue"},
    "setup_title": {"ru": "Подключение к роутеру", "en": "Router connection"},
    "router_ip": {"ru": "IP роутера", "en": "Router IP"},
    "router_user": {"ru": "Имя пользователя", "en": "Username"},
    "router_pass": {"ru": "Пароль", "en": "Password"},
    "interface": {"ru": "Сетевой интерфейс", "en": "Network interface"},
    "capture_all": {"ru": "Перехватывать всю сеть (MITM)", "en": "Capture whole network (MITM)"},
    "capture_all_hint": {
        "ru": "Позволяет видеть запросы других устройств. На Wi-Fi точка доступа может блокировать пересылку — лучше Ethernet.",
        "en": "Lets you see other devices' requests. On Wi-Fi the access point may block forwarding — Ethernet is better.",
    },
    "router_dhcp_table": {
        "ru": "Читать DHCP-таблицу роутера",
        "en": "Read router DHCP table",
    },
    "router_dhcp_table_hint": {
        "ru": "Даёт имена всех устройств. На некоторых прошивках Realtek страница /dhcptbl.asp может зависнуть — включайте осторожно.",
        "en": "Names all devices. On some Realtek firmwares /dhcptbl.asp may hang the router — enable with care.",
    },
    "save_connect": {"ru": "Сохранить и подключиться", "en": "Save and connect"},
    "skip": {"ru": "Пропустить", "en": "Skip"},
    "back": {"ru": "Назад", "en": "Back"},
    "test_connection": {"ru": "Проверить связь", "en": "Test connection"},
    "connection_ok": {"ru": "Связь есть", "en": "Connected"},
    "connection_fail": {"ru": "Не удалось подключиться", "en": "Connection failed"},
    "login_ok": {"ru": "Вход в админку выполнен", "en": "Logged in to admin panel"},
    "login_fail": {"ru": "Вход не выполнен (проверьте пароль)", "en": "Login failed (check password)"},
    "devices_found": {"ru": "Устройств найдено: {n}", "en": "Devices found: {n}"},
    "dashboard_title": {"ru": "Запросы", "en": "Requests"},
    "status_idle": {"ru": "Ожидание", "en": "Idle"},
    "status_running": {"ru": "Захват идёт", "en": "Capturing"},
    "status_stopped": {"ru": "Остановлено", "en": "Stopped"},
    "status_error": {"ru": "Ошибка", "en": "Error"},
    "mode_local": {"ru": "только это устройство", "en": "this device only"},
    "mode_all": {"ru": "вся сеть (MITM)", "en": "whole network (MITM)"},
    "col_time": {"ru": "Время", "en": "Time"},
    "col_device": {"ru": "Устройство", "en": "Device"},
    "col_type": {"ru": "Тип", "en": "Type"},
    "col_request": {"ru": "Запрос", "en": "Request"},
    "col_size": {"ru": "Размер", "en": "Size"},
    "btn_start": {"ru": "Старт", "en": "Start"},
    "btn_stop": {"ru": "Стоп", "en": "Stop"},
    "btn_devices": {"ru": "Устройства", "en": "Devices"},
    "btn_clear": {"ru": "Очистить", "en": "Clear"},
    "btn_setup": {"ru": "Настройки", "en": "Settings"},
    "btn_quit": {"ru": "Выход", "en": "Quit"},
    "btn_language": {"ru": "Язык", "en": "Language"},
    "empty_hint": {"ru": "Запросов пока нет. Нажмите «Старт».", "en": "No requests yet. Press Start."},
    "need_root": {
        "ru": "Для захвата нужны права root. Запустите через ./routerwatch (он использует sudo).",
        "en": "Capture needs root. Run via ./routerwatch (it uses sudo).",
    },
    "mitm_warning": {
        "ru": "MITM включён: трафик сети идёт через этот компьютер. Остановите захват, чтобы вернуть ARP-таблицы.",
        "en": "MITM is on: network traffic flows through this computer. Stop capture to restore ARP tables.",
    },
    "mitm_wifi_warning": {
        "ru": "Вы на Wi-Fi: пересылка между клиентами может не работать. Если сеть пропадёт — нажмите Стоп.",
        "en": "You are on Wi-Fi: client-to-client forwarding may fail. If the network drops, press Stop.",
    },
    "devices_title": {"ru": "Устройства в сети", "en": "Devices on the network"},
    "device_name": {"ru": "Имя", "en": "Name"},
    "device_ip": {"ru": "IP", "en": "IP"},
    "device_mac": {"ru": "MAC", "en": "MAC"},
    "close": {"ru": "Закрыть", "en": "Close"},
    "type_dns": {"ru": "DNS", "en": "DNS"},
    "type_tls": {"ru": "HTTPS", "en": "HTTPS"},
    "type_http": {"ru": "HTTP", "en": "HTTP"},
    "type_other": {"ru": "Другое", "en": "Other"},
    "unknown_device": {"ru": "неизвестно", "en": "unknown"},
    "device_android": {"ru": "Android", "en": "Android"},
    "device_windows_pc": {"ru": "ПК (Windows)", "en": "Windows PC"},
    "device_windows_laptop": {"ru": "Ноутбук (Windows)", "en": "Windows laptop"},
    "device_linux_pc": {"ru": "ПК (Linux)", "en": "Linux PC"},
    "device_phone": {"ru": "Телефон", "en": "Phone"},
    "device_tablet": {"ru": "Планшет", "en": "Tablet"},
    "device_tv": {"ru": "Телевизор", "en": "TV"},
    "device_router": {"ru": "Роутер", "en": "Router"},
    "device_printer": {"ru": "Принтер", "en": "Printer"},
    "device_speaker": {"ru": "Колонка", "en": "Speaker"},
    "device_camera": {"ru": "Камера", "en": "Camera"},
    "device_console": {"ru": "Консоль", "en": "Game console"},
    "device_nas": {"ru": "NAS", "en": "NAS"},
    "device_esp": {"ru": "ESP", "en": "ESP"},
    "device_iot": {"ru": "IoT", "en": "IoT"},
    "device_watch": {"ru": "Часы", "en": "Watch"},
    "device_tv_box": {"ru": "ТВ-приставка", "en": "TV box"},
    "requests_count": {"ru": "Запросов: {n}", "en": "Requests: {n}"},
    "packets_count": {"ru": "Пакетов: {n}", "en": "Packets: {n}"},
    "save_error": {"ru": "Не удалось сохранить настройки: {err}", "en": "Could not save settings: {err}"},
    "lang_changed": {"ru": "Язык изменён", "en": "Language changed"},
    "no_router": {
        "ru": "Роутер не ответил, но захват трафика работает без него.",
        "en": "Router did not respond, but traffic capture works without it.",
    },
    "router_busy": {
        "ru": "Роутер занят: в админке уже открыта сессия. Закройте её или подождите.",
        "en": "Router is busy: an admin session is already open. Close it or wait.",
    },
    "refresh_devices": {"ru": "Обновляю список устройств…", "en": "Refreshing device list…"},
}


def t(lang: str, key: str, **kwargs) -> str:
    entry = STRINGS.get(key)
    if not entry:
        return key
    text = entry.get(lang) or entry.get("en") or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text
