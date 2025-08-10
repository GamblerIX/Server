Write-Host "================================" -ForegroundColor Green
Write-Host "Protobuf 编译器自动安装脚本" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

$protocPath = "C:\protoc"
$zipPath = "$protocPath\protoc.zip"
$url = "https://github.com/protocolbuffers/protobuf/releases/download/v29.5/protoc-29.5-win64.zip"

Write-Host "正在清理旧文件..." -ForegroundColor Yellow
if (Test-Path $protocPath) {
    Remove-Item -Path $protocPath -Recurse -Force
}

Write-Host "正在创建目录..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $protocPath -Force | Out-Null

Write-Host "正在下载 protoc..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $url -OutFile $zipPath
    Write-Host "下载完成！" -ForegroundColor Green
} catch {
    Write-Host "下载失败: $_" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "正在解压..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $zipPath -DestinationPath $protocPath -Force
    Write-Host "解压完成！" -ForegroundColor Green
} catch {
    Write-Host "解压失败: $_" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "正在清理临时文件..." -ForegroundColor Yellow
Remove-Item -Path $zipPath -Force

Write-Host "正在配置环境变量..." -ForegroundColor Yellow
$binPath = "$protocPath\bin"
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*$binPath*") {
    $newPath = "$currentPath;$binPath"
    try {
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
        Write-Host "环境变量配置完成！" -ForegroundColor Green
    } catch {
        Write-Host "环境变量设置需要管理员权限，请以管理员身份运行此脚本" -ForegroundColor Red
    }
}

Write-Host "================================" -ForegroundColor Green
Write-Host "安装完成！" -ForegroundColor Green
Write-Host "请重启命令行，然后输入以下命令验证安装：" -ForegroundColor Green
Write-Host "protoc --version" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Green

pause