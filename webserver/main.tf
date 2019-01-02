# Specify the provider and access details
provider "aws" {
  region = "${var.aws_region}"
  access_key = "keyhere"
  secret_key = "keyhere"
}

# Lookup the correct AMI based on the region specified
data "aws_ami" "amazon_windows_2016" {
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
    # set from default of 5m to 10m to avoid winrm timeout
    timeout = "10m"
  }
  # Change instance type for appropriate use case
  instance_type = "t2.medium"
  ami           = "${data.aws_ami.amazon_windows_2016.image_id}"

  # Root storage
  # Terraform doesn't allow encryption of root at this time
  # encrypt volume after deployment.
  root_block_device {
    volume_type = "gp2"
    volume_size = 40
    delete_on_termination = true
  }

  # Slave storage
  ebs_block_device {
    device_name = "/dev/xvdb"
    volume_type = "sc1"
    volume_size = 40
    encrypted = "true"
    delete_on_termination = true
  }

  # AZ to launch in
  availability_zone = "${var.aws_availzone}"

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
  # Steps for my install are as follows:
  # Adds WinRM Rule
  # Installs Choco | Chrome
  # Provisions and Attaches Slave Storage
  # Installs IIS Roles
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
  $admin.psbase.invoke("SetPassword", "${var.admin_password}")
  Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
  choco install urlrewrite -y
  choco install googlechrome -y
  Initialize-Disk 1 -PartitionStyle GPT
  New-Partition –DiskNumber 1 -UseMaximumSize -AssignDriveLetter
  Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel Data
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment
  Enable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-Security
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-Performance
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-Metabase
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic
  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
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
  $domain = "domain.name.here"
  $password = "password" | ConvertTo-SecureString -asPlainText -Force
  $username = "$domain\username"
  $credential = New-Object System.Management.Automation.PSCredential($username,$password)
  Add-Computer -DomainName $domain -Credential $credential
  Restart-Computer
</powershell>
EOF
}
