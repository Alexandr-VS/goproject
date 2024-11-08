# Генератор и приёмник пакетов

Генератор пакетов предназначен для создания и отправки сетевых пакетов. Он позволяет настраивать различные параметры пакетов, такие как протоколы, порты, адреса и их содержимое. 

Приёмник пакетов позволяет захватывать и анализировать сетевые пакеты.

## Установка

1. Убедитесь, что у вас установлен Go. Для этого можно использовать команду командной строки:
```bash
go
```
Если Go не установлен, воспользуйтесь руководством по его установке: https://go.dev/doc/install

2. Клонируйте себе репозиторий:
```bash
git clone https://github.com/Alexandr-VS/goproject
```

3. Перейдите в директорию проекта с помощью команды:
```bash
cd ./директория, в которую клонировали репозиторий
```

4. Установите зависимости командой:
```bash
go mod tidy
```

5. Понадобится библиотека pcap.h, чтобы её установить, введите команду в командной строке:
```bash
sudo apt-get install libpcap0.8-dev
```

6. Для запуска необходимы права привилегированного пользователя:
```bash
sudo bash
```

7. Убедиться, что поддерживается Go:
```bash
go
```
Если не поддерживается, необходимо в том же привилегированном режиме выполнить следующие команды:
```bash
nano ~/.bashrc
```
В открывшемся текстовом редакторе в конце файла добавить следующие строки:

```
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/goproject
export PATH=$PATH:$GOPATH/bin
```
Сохранить изменения комбинация клавиш: Ctrl+O, Enter, Ctrl+X.
Проверить, что команда ```go``` работает.

8. Запустить receiver и generator из соответствующих директорий:
```bash
go run main.go
```
