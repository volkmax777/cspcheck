#ps2exe -title 'КриптоМАКС' -iconFile .\logo.ico -noOutput -noError  .\cspcheck.ps1 .\cspcheck.exe

Add-Type -AssemblyName System.Windows.Forms

New-Item -ItemType "directory" -Path $env:TEMP\CSPCheck -Force
Set-Location $env:TEMP\CSPCheck

$appname = 'КриптоМАКС'
$cspname = 'КриптоПро CSP'
$plugname = 'КриптоПро ЭЦП Browser plug-in'
$rtknname = 'Драйверы Рутокен'
$csplink = 'https://vdelo.pro/files/dist/cryptopro.exe'
$pluglink = 'https://vdelo.pro/files/dist/cadesplugin.exe'
$rtknlink = 'https://download.rutoken.ru/Rutoken/Drivers/Current/rtDrivers.exe'
$sbisrootcertslink = 'https://update.sbis.ru/ereport/cert/basic/install_certs.exe'
$konturrootcertslink = 'https://ca.kontur.ru/Files/userfiles/file/CertificateInstaller/Certificates_Kontur_21_01_2022.zip'
$konturrootcertsappname = 'Certificates_Kontur_Admin.exe'
$cspargs = '-silent'
$plugargs = '-silent'
$rtknargs = '-silent'

function Is-Installed {
    param (
        $program
    )
    $installed = ""
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture = "32-bit") {
        $installed = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
            Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;
    }
    else {
        $installed = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
            Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;
    }
    return $installed;
}
function Where-Installed( $program ) {
    $path = ''
    if (Is-Installed($program)) {
        if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture = "32-bit") {
            $path = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*") | 
            Where-Object DisplayName -eq $program | 
            Select-Object -ExpandProperty InstallLocation
        }
        else {
            $path = (Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*") | 
            Where-Object DisplayName -eq $program | 
            Select-Object -ExpandProperty InstallLocation
        }
    }
    return $path
}
function Install-App {
    param (
        [string]$appname,
        [string]$applink,
        [string]$instargs
    )
    
    if (!(Is-Installed($appname))) {
        if ([System.Windows.Forms.MessageBox]::Show("$appname не установлен. Установить?", "$appname", 4, [System.Windows.Forms.MessageBoxIcon]::Question) -eq 'yes') {
            try {
                Invoke-WebRequest -URI $applink -outfile app.exe
                try {
                    Start-Process -FilePath .\app.exe -Wait -ArgumentList $instargs
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show("Не удалось установить", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Не удалось скачать", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }
}

function Install-KorturRootCerts {
    if ([System.Windows.Forms.MessageBox]::Show("Установить корневые сертификаты СКБ Контур?", "$appname", 4, [System.Windows.Forms.MessageBoxIcon]::Question) -eq 'yes') {
        try {
            Invoke-WebRequest -URI $konturrootcertslink -outfile app.zip
            try {
                Expand-Archive -Path .\app.zip -Force
                try {
                    Start-Process -FilePath .\app\$konturrootcertsappname -Wait
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show("Не удалось запустить", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Не удалось распаковать архив", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Не удалось скачать", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

function Install-SbisRootCerts {
    if ([System.Windows.Forms.MessageBox]::Show("Установить корневые сертификаты УЦ Тензор?", "$appname", 4, [System.Windows.Forms.MessageBoxIcon]::Question) -eq 'yes') {
        try {
            Invoke-WebRequest -URI $sbisrootcertslink -outfile app.exe
            try {
                Start-Process -FilePath .\app.exe -Wait
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Не удалось запустить", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Не удалось скачать", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

function Test-Complete {
    if ([System.Windows.Forms.MessageBox]::Show("Проверка завершена. Повторить?", "$appname", 5, [System.Windows.Forms.MessageBoxIcon]::Question) -eq 'retry') {
        Main
    }
    else {
        Set-Location $env:TEMP
        Remove-Item -Path $env:TEMP\CSPCheck -Recurse -Force -Verbose
        [System.Windows.Forms.MessageBox]::Show("Работа утилиты завершена", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
}

function Cert-Sign {
    If (Is-Installed($cspname)) {
        $path = Where-Installed($cspname)
        $test = $path + 'csptest.exe'
        $mgr = $path + 'certmgr.exe'
        $certs = & $mgr -list 

        $ifempty = $certs | Select-String 'ErrorCode:' | ForEach-Object -Begin {
            $result = @()
        } -Process {
            $result += ((($_ -split 'ErrorCode: ')[1]) -split ']' )[0]
        } -End {
            $result
        }

        if ($ifempty -eq '0x8010002c') {
            [System.Windows.Forms.MessageBox]::Show("Сертификаты отсутствуют", "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
        else {
            [array]$certnames = $certs | Select-String 'Субъект' | ForEach-Object -Begin {
                $result = @()
            } -Process {
                $result += ((($_ -split 'O="')[1]) -split '",' )[0]
            } -End {
                $result
            }
        
            [array]$certkeys = $certs | Select-String 'SHA1 отпечаток' | ForEach-Object -Begin {
                $result = @()
            } -Process {
                $result += (($_ -split 'SHA1 отпечаток      : ')[1])
            } -End {
                $result
            }
        
            [array]$certdate = $certs | Select-String 'Истекает' | ForEach-Object -Begin {
                $result = @()
            } -Process {
                #$result += (($_ -split 'Истекает            : ')[1])
                $result += ((($_ -split 'Истекает            : ')[1]) -split '  ' )[0]
            } -End {
                $result
            }
        
            [int]$max = $certnames.Count
            if ([int]$certkeys.count -gt [int]$certnames.count) { $max = $certkeys.Count; }
         
            $Results = for ( $i = 0; $i -lt $max; $i++) {
                Write-Verbose "$($certnames[$i]),$($certdate[$i]),$($certkeys[$i])"
                [PSCustomObject]@{
                    Название = $certnames[$i]
                    Истекает = $certdate[$i]
                    Ключ     = $certkeys[$i]
                }
            }
        
            $testsign = $Results | Out-GridView -Title 'Выберите сертификат для проверки' -PassThru | Select-Object Ключ | Out-String
            $testsign = ($testsign -split '\r?\n')[3]
        
            New-Item -Name "testfile.txt" -Value "Тестовый файл" -Force
        
            $signresult = & $test -lowsign -sign -in "testfile.txt" -out "testfile.txt.sig" -my $testsign | Select-String 'ErrorCode:' | ForEach-Object -Begin {
                $result = @()
            } -Process {
                $result += ((($_ -split 'ErrorCode: ')[1]) -split ']' )[0]
            } -End {
                $result
            }
        
            switch ( $signresult ) {
                # Успешное подписание
                '0x00000000' { $result = 'Успешно подписано' }
                # Отменил
                '0x8010006e' { $result = 'Действие отменено пользователем' }
                '0x000000a0' { $result = 'Действие отменено пользователем' }
                # Переустановить плагин
                '0x8007054b' { $result = 'Необходимо переустановить сертификаты' }
                '0x800B010a' { $result = 'Необходимо переустановить сертификаты' }
                '0x8010006b' { $result = 'Необходимо переустановить сертификаты' }
                '0x80070490' { $result = 'Необходимо переустановить сертификаты' }
                # Adblock
                '0x80090016' { $result = 'Необходимо переустановить сертификаты' }
                # Лицензия
                '0x8007065b' { $result = 'Необходимо посмотреть статус лицензий КриптоПро СSP' }
                # актуальность версии
                '0x80090008' { $result = 'Необходимо проверить актуальность версии КриптоПро CSP' }
                # Также следует проверить статус лицензий
                '0x8007064a' { $result = 'Необходимо посмотреть статус лицензий КриптоПро СSP' }
                # истек срок действия сертификата
                '0x80090019' { $result = 'Истек срок действия сертификата' }
                '0x80070002' { $result = 'Истек срок действия сертификата' }
                # срок действия ключа сертификата
                '0x80090010' { $result = 'Необходимо проверить срок действия ключа сертификата' }
                # данные сертификата не совпадают с ЕГРЮЛ или конфликт КриптоПро и VIPNet
                '0x80070057' { $result = 'Конфликт КриптоПро и VIPNet' }
                # нет привязки к закрытому ключу
                '0x8009200b' { $result = 'Нет привязки к закрытому ключу' }
            }
        
            [System.Windows.Forms.MessageBox]::Show($result, "$appname", 0, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    }
}

function Main {
    Install-App -appname $cspname -applink $csplink -instargs $cspargs
    Install-App -appname $plugname -applink $pluglink -instargs $plugargs
    Install-App -appname $rtknname -applink $rtknlink -instargs $rtknargs
    Install-SbisRootCerts
    Install-KorturRootCerts
    Cert-Sign
    Test-Complete
}
Main
