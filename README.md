FileCrypt – Шифратор файлов на 7 языках
Надёжное шифрование файлов с использованием AES-256-GCM и ключом на основе пароля.
Поддерживает потоковую обработку больших файлов, проверку целостности и генерацию случайной соли.
Реализован на семи языках программирования с единым интерфейсом командной строки.

🚀 Возможности
Алгоритм – AES-256-GCM (аутентифицированное шифрование).

Ключ – формируется из пароля и соли через PBKDF2 (100 000 итераций, SHA-256).

Потоковая обработка – файлы шифруются/дешифруются по частям, не загружая весь файл в память.

Формат зашифрованного файла:

Соль (16 байт)

Nonce (12 байт)

Зашифрованные данные

Тег аутентификации (16 байт)

Проверка целостности – при дешифровании автоматически проверяется тег.

Сжатие (опционально) – можно добавить флаг для сжатия перед шифрованием (в реализациях, где есть поддержка).

Единый интерфейс – все версии используют одинаковые команды.

📦 Состав репозитория
Язык	Файл	Статус
Python	filecrypt.py	✅
Go	filecrypt.go	✅
JavaScript	filecrypt.js	✅
C++	filecrypt.cpp	✅
C#	filecrypt.cs	✅
Java	filecrypt.java	✅
Ruby	filecrypt.rb	✅
📖 Использование
Синтаксис (единый для всех версий):

bash
<команда> <режим> <входной_файл> <выходной_файл> <пароль>
Режимы
encrypt – зашифровать файл.

decrypt – расшифровать файл.

Примеры
bash
# Зашифровать файл document.pdf в document.pdf.enc
python filecrypt.py encrypt document.pdf document.pdf.enc MySecretPassword

# Расшифровать файл обратно
python filecrypt.py decrypt document.pdf.enc document_restored.pdf MySecretPassword
Дополнительные опции (в некоторых реализациях)
-c, --compress – сжатие перед шифрованием (если поддерживается).

-h, --help – справка.

🛠 Установка и запуск
Python
bash
pip install cryptography
python filecrypt.py encrypt input output password
Go
bash
go build filecrypt.go
./filecrypt encrypt input output password
JavaScript (Node.js)
bash
npm install crypto-js
node filecrypt.js encrypt input output password
C++
bash
g++ -std=c++11 filecrypt.cpp -lssl -lcrypto -o filecrypt
./filecrypt encrypt input output password
C#
bash
csc filecrypt.cs
mono filecrypt.exe encrypt input output password   # или dotnet run
Java
bash
javac filecrypt.java
java filecrypt encrypt input output password
Ruby
bash
ruby filecrypt.rb encrypt input output password
🧠 Архитектура
Генерация соли – при шифровании создаётся случайная соль (16 байт).

Формирование ключа – пароль + соль → PBKDF2 → 32-байтовый ключ.

Шифрование – AES-256-GCM с случайным nonce (12 байт). Данные шифруются по частям (буфер 64 КБ).

Запись – соль, nonce, шифротекст, тег сохраняются в выходной файл.

Дешифрование – из файла читаются соль, nonce, тег, затем расшифровываются данные и проверяется тег.

Все реализации поддерживают файлы любого размера.

✨ Дополнительные фичи
Автоматическая проверка пароля – при дешифровании неверный пароль вызывает ошибку аутентификации.

Опциональное сжатие (в некоторых версиях) – уменьшает размер зашифрованного файла.

Цветной вывод – сообщения об успехе/ошибке выделяются цветом.

🤝 Вклад в проект
Приветствуются улучшения:

Добавление поддержки асимметричного шифрования.

Интеграция с облачными хранилищами.

Реализация сжатия во всех версиях.

Создавайте Issues и Pull Requests.

📜 Лицензия
MIT License – свободное использование, модификация и распространение.
