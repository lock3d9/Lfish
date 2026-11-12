# LFish

*Educational project*

> [!WARNING]
> **EN:** AI was used for the UI design. Please report any bugs.
>
> **RU:** Дизайн интерфейса создавался с помощью ИИ. Об ошибках сообщайте в Issues.
>
> **UA:** Дизайн інтерфейсу створювався за допомогою ШІ. Про помилки повідомляйте в Issues.

A network traffic analyzer for Linux, written in **Go** and **Wails**.

**Languages:** [English](#english) | [Русский](#русский) | [Українська](#українська)

---

## English

LFish is a network traffic analyzer with simple and advanced modes.

**Features:**
- Live packet capture, PCAP/PCAPNG
- TCP, UDP, DNS, HTTP, TLS
- Packet filters and traffic graphs
- Connection and process tracking
- 3 themes, EN/RU/UA

### Build

Requires Go 1.25+, GCC, Make, GTK 3, WebKitGTK 4.1 and libpcap.

**Arch / CachyOS / Manjaro**
```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

**Ubuntu / Debian / Mint**
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

**Compile and run:**
```bash
git clone https://github.com/lock3d9/LFish.git
cd LFish
make build
./build/bin/lfish
```

> [!NOTE]
> Package names may vary by distribution. Check that Go 1.25+ is installed.

---

## Русский

LFish — анализатор сетевого трафика для Linux с простым и продвинутым режимами.

**Возможности:**
- Захват пакетов, PCAP/PCAPNG
- Анализ TCP, UDP, DNS, HTTP, TLS
- Фильтры и графики трафика
- Отслеживание соединений и процессов
- 3 темы, EN/RU/UA

### Сборка

Требуются Go 1.25+, GCC, Make, GTK 3, WebKitGTK 4.1 и libpcap.

**Arch / CachyOS / Manjaro**
```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

**Ubuntu / Debian / Mint**
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

**Сборка и запуск:**
```bash
git clone https://github.com/lock3d9/LFish.git
cd LFish
make build
./build/bin/lfish
```

> [!NOTE]
> Названия пакетов могут отличаться. Нужен Go 1.25 или новее.

---

## Українська

LFish — аналізатор мережевого трафіку для Linux із простим і розширеним режимами.

**Можливості:**
- Захоплення пакетів, PCAP/PCAPNG
- Аналіз TCP, UDP, DNS, HTTP, TLS
- Фільтри та графіки трафіку
- Відстеження з'єднань і процесів
- 3 теми, EN/RU/UA

### Збірка

Потрібні Go 1.25+, GCC, Make, GTK 3, WebKitGTK 4.1 і libpcap.

**Arch / CachyOS / Manjaro**
```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

**Ubuntu / Debian / Mint**
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

**Збірка та запуск:**
```bash
git clone https://github.com/lock3d9/LFish.git
cd LFish
make build
./build/bin/lfish
```

> [!NOTE]
> Назви пакетів можуть відрізнятися. Потрібен Go 1.25 або новіший.
