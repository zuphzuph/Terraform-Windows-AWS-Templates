# Specify the provider and access details
provider "aws" {
  region = "var.aws_region"
  access_key = "key"
  secret_key = "key"
}

# Lookup the correct AMI based on the region specified
data "aws_ami" "amazon_windows_2019_std" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2016-English-Full-Base-*"]
  }
}

resource "aws_instance" "winrm" {
  # The connection block tells our provisioner how to
  # communicate with the resource (instance)
  # WinRM will not work unless you include a SG here to allow
  # traffic from TCP ports 5985/5986.
  connection {
    type     = "winrm"
    user     = "Administrator"
    password = "${var.admin_password}"
    # Limit for WinRM timeout
    timeout = "10m"
  }
  # Change instance type for appropriate use case
  instance_type = "t2.medium"
  ami           = "data.aws_ami.amazon_windows_2016_std.image_id"

  # Root storage
  # Terraform doesn't allow encryption of root at this time
  # encrypt volume after deployment.
  root_block_device {
    volume_type = "gp2"
    volume_size = 40
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
  key_name = "var.key_name"

# WinRM and PowerShell Provision Functions
  user_data = <<EOF
<script>
  winrm quickconfig -q & winrm set winrm/config @{MaxTimeoutms="1800000"} & winrm set winrm/config/service @{AllowUnencrypted="true"} & winrm set winrm/config/service/auth @{Basic="true"}
</script>
<powershell>
  # Allow WinRM Connection
  netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=72.164.243.226 localip=any action=allow
  
  # Set Default Administrator password
  $admin = [adsi]("WinNT://./administrator, user")
  $admin.psbase.invoke("SetPassword", "var.admin_password")
  
  # Install IIS Features and Roles
  Install-WindowsFeature -name Web-Server -IncludeAllSubFeature -IncludeManagementTools

  # Install Chocolatey and Packages
  Set-ExecutionPolicy Unrestricted -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  choco install urlrewrite -y
  choco install googlechrome -y

  $source = "https://download.microsoft.com/download/C/F/F/CFF3A0B8-99D4-41A2-AE1A-496C08BEB904/WebPlatformInstaller_amd64_en-US.msi"
  $destination = "$env:temp\WebPlatformInstaller_amd64_en-US.msi" 
  $wc = New-Object System.Net.WebClient 
  $wc.DownloadFile($source, $destination)
  Start-Process -FilePath $destination -ArgumentList "/quiet" -wait
  $WebPiCMd = 'C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe'
  Start-Process -wait -FilePath $WebPiCMd -ArgumentList "-WindowStyle Hidden /install /Products:UrlRewrite2 /AcceptEula /OptInMU /SuppressPostFinish" 

  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules" -name "." -value @{name='HTTP to HTTPS Redirect'; patternSyntax='ECMAScript'; stopProcessing='True'}
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules/rule[@name='HTTP to HTTPS Redirect']/match" -name url -value "(.*)"
  Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/rewrite/GlobalRules/rule[@name='HTTP to HTTPS Redirect']/conditions" -name "." -value @{input="{HTTPS}"; pattern='^OFF$'}
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "type" -value "Redirect"
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "url" -value "https://{HTTP_HOST}/{R:1}"
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/rewrite/globalRules/rule[@name='HTTP to HTTPS Redirect']/action" -name "redirectType" -value "SeeOther" 
  
  # Disable IE Security Function
  function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
  }
  
  # Disable UAC Function
  function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
  }

  # Disable IE Sec and UAC
  Disable-InternetExplorerESC
  Disable-UserAccessControl

  #Set Time Zone
  Set-TimeZone -Name "Mountain Standard Time"

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
