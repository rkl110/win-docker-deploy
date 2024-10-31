# Last Update: 2024-10-26
# Powershell Script to deploy Docker and run as a non-admin user
#Requires -RunAsAdministrator

######################################
# Setup Variables
$docker_source = "https://download.docker.com/win/static/stable/x86_64/"
$docker_version = "docker-27.3.1.zip"
$docker_url = "$docker_source$docker_version"
$docker_zip = "$env:TEMP\$docker_version"
$default_path = "$env:ProgramFiles\Docker"
$default_user = "$env:USERNAME"
$default_installService = 'Y'
$default_psExecutable = "$PSHome\pwsh.exe"
$default_docker_data = "$env:ProgramData\Docker"

######################################
# Prepare and get all the required information

# Check if script is running as an admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$adminUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as an administrator." -ForegroundColor Red
    exit
}
else {
    $adminUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "Script is running as administrator: $adminUser" -ForegroundColor Green
}

# Get user to run Docker
$unprivileged_user = Read-Host "Please enter unprivileged username who will run Docker (default: $default_user)"
if ([string]::IsNullOrWhiteSpace($default_user)) {
    $unprivileged_user = $default_user
}
Write-Host "Unprivileged user: $unprivileged_user"

# Get path to install Docker
$install_path = Read-Host "Please enter the path to install Docker (default: $default_path)"
if ([string]::IsNullOrWhiteSpace($install_path)) {
    $install_path = $default_path
}
Write-Host "Install path: $install_path"

# Prompt to install Docker as a service
$installService = Read-Host "Install Docker as a service? (Y/N) (default: $default_installService)"
if ([string]::IsNullOrWhiteSpace($installService)) {
    $installService = $default_installService
}
$dockerService = Get-Service -Name "docker" -ErrorAction SilentlyContinue
if ($installService -eq 'Y' -or $installService -eq 'y') {
    Write-Host "Install Docker as a service..."
    if ($null -ne $dockerService) {
        Write-Host "Docker service already exists, skipping later" -ForegroundColor Red
    }
}
else {
    Write-Host "Docker will not be installed as a service."
}

# Get powershell executable
$psExecutable = Read-Host "Please enter the path to your powershell (default: $default_psExecutable)"
if ([string]::IsNullOrWhiteSpace($psExecutable)) {
    $psExecutable = $default_psExecutable
}
Write-Host "Powershell executable: $psExecutable"

######################################
# Start the installation process

# Check if install_path exists and create directory if it does not
if (-not (Test-Path -Path $install_path)) {
    New-Item -Path $install_path -ItemType Directory | Out-Null
    Write-Host "Created directory: $install_path"
}
else {
    Write-Host "Directory already exists: $install_path"
}

# Download and install Docker
Write-Host "Downloading Docker from $docker_url..."
Invoke-WebRequest -Uri $docker_url -OutFile $docker_zip
Write-Host "Download complete."

Write-Host "Unzipping Docker to $install_path..."
Expand-Archive -Path $docker_zip -DestinationPath $install_path -Force
Write-Host "Unzip complete."

# Stop Docker service if it is running
if ($dockerService -and $dockerService.Status -eq 'Running') {
    Write-Host "Docker service is already running. Stoping docker..." -ForegroundColor Yellow
    Stop-Service -Name "docker" -Force
}

# Move the files to the install path and clean up old files
Get-ChildItem -Path "$install_path/docker" -File | ForEach-Object {
    $destinationPath = Join-Path -Path $install_path -ChildPath $_.Name
    if (Test-Path -Path $destinationPath) {
        Remove-Item -Path $destinationPath -Force
    }
    Move-Item -Path $_.FullName -Destination $install_path -Force
}
Write-Host "Moved files to $install_path"
Remove-Item -Path $install_path/docker -Recurse -Force

# Clean up the zip file
Remove-Item -Path $docker_zip

# Check if Hyper-V is enabled
$hypervFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($hypervFeature.State -ne 'Enabled') {
    Write-Host "Hyper-V is not enabled. Enabling Hyper-V..."
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
    Write-Host "Hyper-V has been enabled. Please restart your computer to apply the changes."
    exit
}
else {
    Write-Host "Hyper-V is already enabled."
}

# Check if Containers feature is enabled
$containersFeature = Get-WindowsOptionalFeature -Online -FeatureName Containers
if ($containersFeature.State -ne 'Enabled') {
    Write-Host "Containers feature is not enabled. Enabling Containers..."
    Enable-WindowsOptionalFeature -Online -FeatureName Containers -NoRestart
    Write-Host "Containers feature has been enabled. Please restart your computer to apply the changes."
    exit
}
else {
    Write-Host "Containers feature is already enabled."
}

# Add $install_path to the system environment Path variable
$pathEnv = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Process)
$pathList = $pathEnv -split ';'

# Check if $install_path is in the list of paths
if ($pathList -contains $install_path) {
    Write-Host "$install_path is already in the PATH variable."
}
else {
    Write-Host "$install_path is not in the PATH."
    $newPath = "$pathEnv;$install_path"
    [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)
    Write-Host "Added $install_path to the system PATH variable."
    # Update the PATH for the current process
    [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Process)
    Write-Host "Updated the PATH variable for the current session."
}
if ($null -eq $dockerService) {
    # Deploy Service
    if ($installService -eq 'Y' -or $installService -eq 'y') {
        Write-Host "Installing Docker as a service..."
        Start-Process -FilePath $install_path\dockerd.exe -ArgumentList "--register-service"
    }
    else {
        Write-Host "Skip installing Docker as a service..."
    }
}
else {
    Write-Host "Docker service already exists..."
}

# Check if the scheduled task "FixDockerPipePermissions" exists
$taskName = "FixDockerPipePermissions"
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $taskExists) {
    Write-Host "Scheduled task $taskName does not exist, deploying..."

    # Define the content to write to the file
    $content = @"
# Script to fix Docker pipe permissions for non-privileged user

`$account="$env:USERDOMAIN\$unprivileged_user"
`$npipe = "\\.\pipe\docker_engine"
`$dInfo = New-Object "System.IO.DirectoryInfo" -ArgumentList `$npipe
`$dSec = Get-Acl -Path `$dInfo
`$fullControl =[System.Security.AccessControl.FileSystemRights]::FullControl
`$allow =[System.Security.AccessControl.AccessControlType]::Allow
`$rule = New-Object "System.Security.AccessControl.FileSystemAccessRule" -ArgumentList `$account,`$fullControl,`$allow
`$dSec.AddAccessRule(`$rule)
Set-Acl -Path `$dInfo -AclObject `$dSec
"@

    # Deploy script to acces docker as non privileged user
    $filePath = "$install_path/fix_docker_pipe_permissions.ps1"
    $content | Out-File -FilePath $filePath -Force
    Write-Host "Script has been deployed to $filePath"

    # Create a scheduled task to run the script after Docker starts
    $ActionParameters = @{
        Execute          = $psExecutable
        Argument         = "-ExecutionPolicy Bypass -NonInteractive -NoLogo -NoProfile -Command `".\fix_docker_pipe_permissions.ps1; exit `$LASTEXITCODE`""
        WorkingDirectory = $install_path
    }

    $Action = New-ScheduledTaskAction @ActionParameters
    #$Principal = New-ScheduledTaskPrincipal -UserId $adminUser -LogonType Password -RunLevel Highest
    $Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
    $Settings = New-ScheduledTaskSettingsSet

    # Create a scheduled task trigger
    $class = Get-cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
    $trigger = $class | New-CimInstance -ClientOnly
    $trigger.Enabled = $true
    $trigger.Delay = 'PT5S'
    $trigger.Subscription = @'
<QueryList><Query Id="0" Path="Application"><Select Path="Application">*[System[Provider[@Name='docker'] and EventID=11]]</Select></Query></QueryList>
'@

    $RegSchTaskParameters = @{
        TaskName    = $taskName
        Description = 'Allow to access Docker pipe for non-privileged user'
        TaskPath    = '\'
        Action      = $Action
        Principal   = $Principal
        Settings    = $Settings
        Trigger     = $Trigger
    }

    Register-ScheduledTask @RegSchTaskParameters
    Disable-ScheduledTask -TaskName $taskName
    Write-Host "Scheduled task has been created to run the script after Docker starts."
}
else {
    Write-Host "Scheduled task '$taskName' already exists, skip install" -ForegroundColor Red
}

$dockerGroup = "docker-users"
# Check if C:\ProgramData\Docker\config exists and create directory if it does not
if (-not (Test-Path -Path $default_docker_data\config\Readme.md)) {
    New-Item -Path $default_docker_data\config -ItemType Directory | Out-Null
    Write-Host "Created directory: $default_docker_data\config"

    $content = @"
# Readme for Docker configuration files

Settings for Dockerd can be configured in the configuration file `daemon.json`.
See the documentation for more information:
https://docs.docker.com/reference/cli/dockerd/#/windows-configuration-file
https://learn.microsoft.com/de-de/virtualization/windowscontainers/manage-docker/configure-docker-daemon

You might configure the following settings in `daemon.json` to allow non-admin users access Docker:

{
    "group" : "$dockerGroup"
}

Or activate the Scheduled Task "$taskName" to allow $unprivileged_user to access Docker.

"@

    $filePath = "$default_docker_data\config\Readme.md"
    $content | Out-File -FilePath $filePath -Force
    Write-Host "Readme file has been deployed to $filePath"
}

# Check if the 'docker' group exists or create if it does not
$group = Get-LocalGroup -Name $dockerGroup -ErrorAction SilentlyContinue
if (-not $group) {
    New-LocalGroup -Name $dockerGroup
    Write-Host "Created group: $dockerGroup"
    Add-LocalGroupMember -Group $dockerGroup -Member $env:USERDOMAIN\$unprivileged_user -ErrorAction SilentlyContinue
    Write-Host "Added user '$env:USERDOMAIN\$unprivileged_user' to group '$dockerGroup'."
}
else {
    Write-Host "Group '$dockerGroup' already exists."
    $userInGroup = Get-LocalGroupMember -Group $dockerGroup -Member $unprivileged_user -ErrorAction SilentlyContinue
    if (-not $userInGroup) {
        Add-LocalGroupMember -Group $dockerGroup -Member $env:USERDOMAIN\$unprivileged_user -ErrorAction SilentlyContinue
        Write-Host "Added user '$env:USERDOMAIN\$unprivileged_user' to group '$dockerGroup'."
    }
    else {
        Write-Host "User '$env:USERDOMAIN\$unprivileged_user' is already in group '$dockerGroup'."
    }
}

# End of the script, Start Docker service or restart the computer
if (($hypervFeature.State -eq 'Enabled') -and ($containersFeature.State -eq 'Enabled')) {
    Write-Host "Hyper-V and Containers already enabled."
    Write-Host "Starting Docker service..."
    Start-Service -Name "docker"
    Write-Host "Setup Docker has been completed.`n`n`n" -ForegroundColor Green
    "$default_docker_data\config\Readme.md"
    Get-Content -Path "$default_docker_data\config\Readme.md"
}
else {
    Write-Host "Please restart your computer to apply the changes and enjoy Docker." -ForegroundColor Yellow
    Write-Host "Setup Docker has been completed.`n`n`n" -ForegroundColor Green
    "$default_docker_data\config\Readme.md"
    Get-Content -Path "$default_docker_data\config\Readme.md"
}
