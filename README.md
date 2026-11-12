# LFish

> [!WARNING]
> **English (EN)**
>
> AI was used to develop the interface design. Please report any bugs you encounter.
>
> **Русский (RU)**
>
> При разработке дизайна интерфейса использовался искусственный интеллект. Пожалуйста, сообщайте о найденных ошибках.
>
> **Українська (UA)**
>
> Під час розробки дизайну інтерфейсу використовувався штучний інтелект. Будь ласка, повідомляйте про знайдені помилки.

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

**Build:** See [Building on Linux](#building-on-linux).

## Русский

LFish — анализатор сетевого трафика для Linux с простым и продвинутым режимами.

**Возможности:**
- Захват пакетов и поддержка PCAP/PCAPNG
- Анализ TCP, UDP, DNS, HTTP и TLS
- Фильтрация пакетов и графики трафика
- Отслеживание соединений и процессов
- Три темы оформления и поддержка языков

**Сборка:** См. [Building on Linux](#building-on-linux).

## Українська

LFish — аналізатор мережевого трафіку для Linux із простим і розширеним режимами.

**Можливості:**
- Захоплення пакетів і підтримка PCAP/PCAPNG
- Аналіз TCP, UDP, DNS, HTTP і TLS
- Фільтрація пакетів і графіки трафіку
- Відстеження з'єднань і процесів
- Три теми оформлення та підтримка мов

**Збірка:** Див. [Building on Linux](#building-on-linux).

---

## Building on Linux

LFish can be built on multiple Linux distributions.

**Requirements:**
- Linux (x86_64 or ARM64, depending on dependency support)
- Go 1.25+
- GCC and Make
- GTK 3
- WebKitGTK 4.1
- libpcap

### 1. Install dependencies

**Arch Linux / CachyOS / Manjaro**

```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

**Ubuntu / Debian / Linux Mint**

```bash
sudo apt update
sudo apt install golang-go build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libpcap-dev
```

**Fedora**

```bash
sudo dnf install golang gcc make pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libpcap-devel
```

**openSUSE**

```bash
sudo zypper install go gcc make pkg-config gtk3-devel libwebkit2gtk-4_1-0-devel libpcap-devel
```

> [!NOTE]
> Package availability and Go versions depend on your distribution and release. Make sure Go 1.25+ and WebKitGTK 4.1 are available.

### 2. Clone repository

```bash
git clone https://github.com/USERNAME/LFish.git
cd LFish
```

Replace `USERNAME` with the repository owner's GitHub username.

### 3. Build

```bash
make build
```

The executable will be available at:

```text
build/bin/lfish
```

### 4. Run

```bash
./build/bin/lfish
```

### Compatibility

LFish uses CGO and native Linux libraries.

- The executable is not fully static.
- GTK 3, WebKitGTK 4.1 and libpcap are required at runtime.
- Binaries built on one distribution may not work on another.
- For maximum compatibility, build LFish directly on your distribution.
- Building for another CPU architecture requires a compatible cross-compilation environment.

---

**Status:** In development.
