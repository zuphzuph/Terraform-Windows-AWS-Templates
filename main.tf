# Specify the provider and access details
provider "aws" {
  region = "var.aws_region"
  access_key = "key"
  secret_key = "key"
}

# Lookup the correct AMI based on the region specified
data "aws_ami" "amazon_windows_2019_sql_2017_std" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-SQL_2017_Standard-*"]
  }
}

resource "aws_instance" "winrm" {
  # The connection block tells our provisioner how to
  # communicate with the resource (instance)
  connection {
    type     = "winrm"
    user     = "Administrator"
    password = "var.admin_password"
    # set from default of 5m to 10m to avoid winrm timeout
    timeout = "10m"
  }

  instance_type = "m4.large"
  ami           = "data.aws_ami.amazon_windows_2019_sql_2017_std.image_id"

  # Root storage
  # Terraform doesn't allow encryption of root at this time
  # encrypt volume after deployment.
  root_block_device {
    volume_type = "gp2"
    volume_size = 60
    delete_on_termination = true
  }

  # Slave Storage
  ebs_block_device {
    device_name = "/dev/xvdb"
    volume_type = "sc1"
    volume_size = 500
    encrypted = "true"
    delete_on_termination = true
  }

  # AZ to launch in
  availability_zone = "var.aws_availzone"

  # VPC subnet and SGs
  subnet_id = "subnet-XXXXX"
  vpc_security_group_ids = ["sg-XXXXX","sg-XXXXX","sg-XXXXX"]
  associate_public_ip_address = "true"

  # The name of our SSH keypair you've created and downloaded
  # from the AWS console.
  #
  # https://console.aws.amazon.com/ec2/v2/home?region=us-west-2#KeyPairs
  #
  key_name = "${var.key_name}"

  # Note that terraform uses Go WinRM which doesn't support https at this time. If server is not on a private network,
  # recommend bootstraping Chef via user_data.  See asg_user_data.tpl for an example on how to do that.
  # Strip anything you don't need/want below. 
  # Steps below are as follows:
  # Adds WinRM Rule
  # Installs Choco
  # Provisions and Attaches MSSQL Slave Storage and Creates Dirs
  # Sets Default Directories in MSSQL to D:\*
  # Disables IE Enhanced Secrity
  # Joins Specified Domain
  user_data = <<EOF
<script>
  winrm quickconfig -q & winrm set winrm/config @{MaxTimeoutms="1800000"} & winrm set winrm/config/service @{AllowUnencrypted="true"} & winrm set winrm/config/service/auth @{Basic="true"}
</script>
<powershell>
  netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=any localip=any action=allow
  # Set Administrator password
  $admin = [adsi]("WinNT://./administrator, user")
  $admin.psbase.invoke("SetPassword", "var.admin_password")
  # Install Chocolatey for Package Mgmt
  Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  # Partition, Mount and Create Directories
  Initialize-Disk 1 -PartitionStyle GPT
  New-Partition –DiskNumber 1 -UseMaximumSize -AssignDriveLetter
  Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel SQL-Stuff
  New-Item -ItemType directory -Path D:\Data
  New-Item -ItemType directory -Path D:\Backup
  New-Item -ItemType directory -Path D:\Log
  # Set Default Paths for MSSQL Dirs
  $DataRegKeyPath = "HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer"
  $DataRegKeyName = "DefaultData"
  $DataDirectory = "D:\Data"
    If ((Get-ItemProperty -Path $DataRegKeyPath -Name $DataRegKeyName -ErrorAction SilentlyContinue) -eq $null) {
    New-ItemProperty -Path $DataRegKeyPath -Name $DataRegKeyName -PropertyType String -Value $DataDirectory
      } Else {
      Set-ItemProperty -Path $DataRegKeyPath -Name $DataRegKeyName -Value $DataDirectory
  }
  $LogRegKeyPath = "HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer"
  $LogRegKeyName = "DefaultLog"
  $LogDirectory = "D:\Log"
    If ((Get-ItemProperty -Path $LogRegKeyPath -Name $LogRegKeyName -ErrorAction SilentlyContinue) -eq $null) {
    New-ItemProperty -Path $LogRegKeyPath -Name $LogRegKeyName -PropertyType String -Value $LogDirectory
      } Else {
      Set-ItemProperty -Path $LogRegKeyPath -Name $LogRegKeyName -Value $LogDirectory
  }
  $BackupRegKeyPath = "HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer"
  $BackupRegKeyName = "BackupDirectory"
  $BackupDirectory = "D:\Backup"
    If ((Get-ItemProperty -Path $BackupRegKeyPath -Name $BackupRegKeyName -ErrorAction SilentlyContinue) -eq $null) {
    New-ItemProperty -Path $BackupRegKeyPath -Name $BackupRegKeyName -PropertyType String -Value $BackupDirectory
      } Else {
      Set-ItemProperty -Path $BackupRegKeyPath -Name $BackupRegKeyName -Value $BackupDirectory
  }
  # Disable IE Enhanced Protection Mode
  function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
  }
  function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
  }
  Disable-UserAccessControl
  Disable-InternetExplorerESC
  # Join EC2 Instance to Domain
  $domain = "domain.name.here"
  $password = "password" | ConvertTo-SecureString -asPlainText -Force
  $username = "$domain\username"
  $credential = New-Object System.Management.Automation.PSCredential($username,$password)
  Add-Computer -DomainName $domain -Credential $credential
  Restart-Computer
</powershell>
EOF
}
