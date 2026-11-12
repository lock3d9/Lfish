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

---

## English

LFish is a desktop network traffic analyzer with simple and advanced modes.

**Features:**
- Live packet capture and PCAP/PCAPNG support
- TCP, UDP, DNS, HTTP and TLS analysis
- Packet filtering and traffic graphs
- Connection tracking and process detection
- Three themes and multilingual interface

### Building on Linux

**Requirements:**
- Linux
- Go 1.25+
- GCC, Make and pkg-config
- GTK 3
- WebKitGTK 4.1
- libpcap

**1. Install dependencies**

Arch Linux / CachyOS / Manjaro:

```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

Ubuntu / Debian / Linux Mint:

```bash
sudo apt update
sudo apt install golang-go build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libpcap-dev
```

Fedora:

```bash
sudo dnf install golang gcc make pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libpcap-devel
```

openSUSE:

```bash
sudo zypper install go gcc make pkg-config gtk3-devel libwebkit2gtk-4_1-0-devel libpcap-devel
```

**2. Clone the repository**

```bash
git clone https://github.com/USERNAME/LFish.git
cd LFish
```

Replace `USERNAME` with the GitHub repository owner's username.

**3. Build and run**

```bash
make build
./build/bin/lfish
```

### Compatibility

LFish uses CGO and native Linux libraries.

- GTK 3, WebKitGTK 4.1 and libpcap are required.
- The executable is not fully static.
- Binaries may not work across different distributions.
- Building directly on your distribution is recommended.
- Cross-compilation requires the appropriate native libraries and toolchain.

> [!NOTE]
> Package names and availability may vary depending on your Linux distribution and version. Ensure Go 1.25+ is installed.

---

## Русский

LFish — настольный анализатор сетевого трафика для Linux с простым и продвинутым режимами.

**Возможности:**
- Захват пакетов и поддержка PCAP/PCAPNG
- Анализ TCP, UDP, DNS, HTTP и TLS
- Фильтрация пакетов и графики трафика
- Отслеживание соединений и процессов
- Три темы оформления и многоязычный интерфейс

### Сборка на Linux

**Требования:**
- Linux
- Go 1.25+
- GCC, Make и pkg-config
- GTK 3
- WebKitGTK 4.1
- libpcap

**1. Установка зависимостей**

Arch Linux / CachyOS / Manjaro:

```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

Ubuntu / Debian / Linux Mint:

```bash
sudo apt update
sudo apt install golang-go build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libpcap-dev
```

Fedora:

```bash
sudo dnf install golang gcc make pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libpcap-devel
```

openSUSE:

```bash
sudo zypper install go gcc make pkg-config gtk3-devel libwebkit2gtk-4_1-0-devel libpcap-devel
```

**2. Клонирование репозитория**

```bash
git clone https://github.com/USERNAME/LFish.git
cd LFish
```

Замените `USERNAME` на имя владельца репозитория GitHub.

**3. Сборка и запуск**

```bash
make build
./build/bin/lfish
```

### Совместимость

LFish использует CGO и системные библиотеки Linux.

- Для работы необходимы GTK 3, WebKitGTK 4.1 и libpcap.
- Исполняемый файл не является полностью статическим.
- Бинарные файлы могут быть несовместимы с другими дистрибутивами.
- Рекомендуется собирать программу непосредственно на своём дистрибутиве.
- Для кросс-компиляции необходимы соответствующие библиотеки и инструменты сборки.

> [!NOTE]
> Названия и доступность пакетов могут отличаться в зависимости от дистрибутива и его версии. Убедитесь, что установлен Go 1.25 или новее.

---

## Українська

LFish — настільний аналізатор мережевого трафіку для Linux із простим і розширеним режимами.

**Можливості:**
- Захоплення пакетів і підтримка PCAP/PCAPNG
- Аналіз TCP, UDP, DNS, HTTP і TLS
- Фільтрація пакетів і графіки трафіку
- Відстеження з'єднань і процесів
- Три теми оформлення та багатомовний інтерфейс

### Збірка на Linux

**Вимоги:**
- Linux
- Go 1.25+
- GCC, Make і pkg-config
- GTK 3
- WebKitGTK 4.1
- libpcap

**1. Встановлення залежностей**

Arch Linux / CachyOS / Manjaro:

```bash
sudo pacman -S go gcc make pkgconf gtk3 webkit2gtk-4.1 libpcap
```

Ubuntu / Debian / Linux Mint:

```bash
sudo apt update
sudo apt install golang-go build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libpcap-dev
```

Fedora:

```bash
sudo dnf install golang gcc make pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel libpcap-devel
```

openSUSE:

```bash
sudo zypper install go gcc make pkg-config gtk3-devel libwebkit2gtk-4_1-0-devel libpcap-devel
```

**2. Клонування репозиторію**

```bash
git clone https://github.com/USERNAME/LFish.git
cd LFish
```

Замініть `USERNAME` на ім'я власника репозиторію GitHub.

**3. Збірка та запуск**

```bash
make build
./build/bin/lfish
```

### Сумісність

LFish використовує CGO та системні бібліотеки Linux.

- Для роботи необхідні GTK 3, WebKitGTK 4.1 і libpcap.
- Виконуваний файл не є повністю статичним.
- Бінарні файли можуть бути несумісними з іншими дистрибутивами.
- Рекомендується збирати програму безпосередньо на своєму дистрибутиві.
- Для кроскомпіляції потрібні відповідні бібліотеки та інструменти збірки.

> [!NOTE]
> Назви та доступність пакетів можуть відрізнятися залежно від дистрибутива та його версії. Переконайтеся, що встановлено Go 1.25 або новішу версію.
