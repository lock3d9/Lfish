# LFish

> [!WARNING]
> AI was used to develop the interface design, so please report any bugs.
> При разработке дизайна интерфейса использовался искусственный интеллект, поэтому, пожалуйста, сообщайте о любых ошибках.
> Для розробки дизайну інтерфейсу використовувався штучний інтелект, тому, будь ласка, повідомляйте про будь-які помилки.

A lightweight network traffic analyzer for Linux, built with **Go** and **Wails**.

**Language:** [English](#english) | [Русский](#русский) | [Українська](#українська)

## English

LFish is a desktop network traffic analyzer with simple and advanced modes.

**Features:**
- Live packet capture and PCAP/PCAPNG support
- TCP, UDP, DNS, HTTP and TLS analysis
- Packet filtering and traffic graphs
- Connection tracking and process detection
- Three themes and multilingual interface

**Build (Arch Linux):**
```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
make build
./build/bin/lfish
```

## Русский

LFish — анализатор сетевого трафика для Linux с простым и продвинутым режимами.

**Возможности:**
- Захват пакетов и поддержка PCAP/PCAPNG
- Анализ TCP, UDP, DNS, HTTP и TLS
- Фильтрация пакетов и графики трафика
- Отслеживание соединений и процессов
- Три темы оформления и поддержка языков

**Сборка (Arch Linux):**
```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
make build
./build/bin/lfish
```

## Українська

LFish — аналізатор мережевого трафіку для Linux із простим і розширеним режимами.

**Можливості:**
- Захоплення пакетів і підтримка PCAP/PCAPNG
- Аналіз TCP, UDP, DNS, HTTP і TLS
- Фільтрація пакетів і графіки трафіку
- Відстеження з'єднань і процесів
- Три теми оформлення та підтримка мов

**Збірка (Arch Linux):**
```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
make build
./build/bin/lfish
```

---

**Requirements:** Linux, Go 1.25+, GTK 3, WebKitGTK 4.1, libpcap.

**Status:** In development.
