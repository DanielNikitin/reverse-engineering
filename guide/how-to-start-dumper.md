
Il2CppInspector.Redux.CLI.exe

Вариант 1 (проще): прямая ссылка из самой ошибки:
https://aka.ms/dotnet-core-applaunch?framework=Microsoft.AspNetCore.App&framework_version=10.0.0&arch=x64&rid=win-x64&os=win10

Получить обратную связь сборки

cd D:\Programs\Il2CppInspectorRedux.CLI-win-x64
.\Il2CppInspector.Redux.CLI.exe --help

process <пути>	Принимает оба файла через пробел, сам разбирается, где код, а где метаданные
-o	Папка для результата
-s	C#-описание классов со смещениями (аналог dump.cs)
-m	Метаданные для дизассемблера: скрипт и JSON для IDA
--disassembler	Для какого дизассемблера делать скрипт


=== Сделай рабочую папку с копиями
New-Item -ItemType Directory D:\RustDump
Copy-Item D:\Rust\GameAssembly.dll D:\RustDump\
Copy-Item D:\Rust\RustClient_Data\il2cpp_data\Metadata\global-metadata.dat D:\RustDump\


=== Запусти дамп
cd D:\Programs\Il2CppInspectorRedux.CLI-win-x64
.\Il2CppInspector.Redux.CLI.exe process D:\RustDump\GameAssembly.dll D:\RustDump\global-metadata.dat -o D:\RustDump\out -s -m --disassembler IDA


=== Что смотреть в результате
Открой D:\RustDump\out

===================================== 