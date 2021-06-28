[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

Add-Type -AssemblyName PresentationFramework

#Function used to pull processes running on machines on a network
function Get-WmiProcess 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject win32_Process | 
                Select-Object Name, 
                              ProcessID,
                              @{name       ='ParentProcessName'
                                expression ={If ((Get-Process -id $_.ParentProcessID).Name) {(Get-Process -id $_.ParentProcessID).Name}
                                else {Write-Output "?"}}}, 
                                ParentProcessID, 
                                Path, 
                                CommandLine,
                              @{name       = "hash"
                                expression = {If (Get-Command Get-FileHash) {(Get-FileHash -Algorithm MD5 -Path $_.Path).hash}
                                              else {(certutil.exe -hashfile $_.Path SHA256)[1] -replace " ",""}}},
                              @{name       = "Owner"
                                expression = {@($_.getowner().domain, $_.getowner().user) -join "\"}
                              }
                             
                              
        }
    }
}


#Function used to pull services running on machines on a network
function Get-WmiService 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    ) 
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject win32_Service | 
                Select-Object Name,
                              @{n='PathName';e={($_.PathName.toLower())}},
                              State,
                              StartMode,
                              StartName,
                              ProcessId,
                              @{n='ProcessName';e={(Get-Process -id $_.ProcessId | Select Name).Name}}

        }
    }
}


function Get-Connection
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-NetTCPConnection -State Established | 
            Select-Object -Property LocalAddress, LocalPort, RemoteAddress, 
            RemotePort, State, OwningProcess, @{name='Process';expression={(Get-Process -Id $_.OwningProcess).Name}}, CreationTime 
        }
     }
        
} 


function Get-LUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
           
        }
        
    } 
} 


function Get-LoggedOnUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            try
            {query user}
            catch
            {Get-CimInstance -Class Win32_ComputerSystem | Select-Object Username}
        }
    }    
} 


function Get-LGroup
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject -Class Win32_Group  
        }
    }    
} 


function Get-LGroupMembers
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            try
            {foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
             [PSCustomObject]@{
             GroupName = $name 
             Member    = (Get-LocalGroupMember $name)}                                   
             }}
      
            catch
            {foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
             [PSCustomObject]@{
             GroupName = $name 
             Member    = Get-WmiObject win32_groupuser | Where-Object {$_.groupcomponent -like "*$name*"} | ForEach-Object {  
             $_.partcomponent –match ".+Domain\=(.+)\,Name\=(.+)$" > $null  
             $matches[1].trim('"') + "\" + $matches[2].trim('"')  
             }  
   
             }
             }}
        }
        
    } 
} 


function Get-SchTask
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            Get-ScheduledTask
            
        }
    }    
}


function Get-Autoruns
{
    [cmdletbinding()]
    Param
    (
        
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
         $regKeyArray = @("HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
          "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
          "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
          "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", 
          "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
          "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", 
          "HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",
          "HKCU:\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices")

         Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($key in $using:regKeyArray)
                {
                    Get-ItemProperty -Path $key
                }
            
        }
    }   
} 

#Found Survey-Firwall function at https://github.com/ralphmwr/PowerShell-ThreatHunting/blob/master/Survey.psm1
function Survey-Firewall
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $rules         = Get-NetFirewallRule | Where-Object {$_.enabled}
            $portfilter    = Get-NetFirewallPortFilter
            $addressfilter = Get-NetFirewallAddressFilter

            foreach ($rule in $rules) {
                $ruleport    = $portfilter | Where-Object {$_.InstanceID -eq $rule.instanceid}
                $ruleaddress = $addressfilter | Where-Object {$_.InstanceID -eq $rule.instanceid}
                $data = @{
                    InstanceID    = $rule.instanceid.tostring()
                    Direction     = $rule.direction.tostring()
                    Action        = $rule.action.tostring()
                    LocalAddress  = $ruleaddress.LocalAddress.tostring()
                    RemoteAddress = $ruleaddress.RemoteAddress.tostring()
                    Protocol      = $ruleport.Protocol.tostring()
                    LocalPort     = $ruleport.LocalPort -join ","
                    RemotePort    = $ruleport.RemotePort -join ","
                }
                New-Object -TypeName psobject -Property $data
            }
        }
    }
}

<#This function will perform a dir walk of hosts on a network
By using the .NET System.IO.Direction, the function is over 100x faster than using Get-ChildItem #>
 function Get-DirWalk
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential,

        [string]
        $path
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $files = [System.IO.Directory]::EnumerateFiles($using:path,'*.*','AllDirectories')
            
            foreach ($file in $files) {
                
                    [PSCustomObject]@{
                        Name = $file }
            }       
            
        }
    }
        
}


<#This function will take a dir walk and collect hashes
By using the .NET System.IO.Direction, the function is much faster than Get-FileHash #>

function Get-DirWalkHash
{
    [cmdletbinding()]
    Param
    (   [Parameter(ValueFromPipeline=$true)]

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential,

        [string]
        $path,
        
         [string]
        $algorithm = 'SHA1'
    )

    Process
    {   
        
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $files = [System.IO.Directory]::EnumerateFiles($using:path,'*.*','AllDirectories')
            
            $files = foreach ($file in $files) {
                    [PSCustomObject]@{
                        Name = $file
                        }
                     }
            
            foreach($file in $files) {
               [PSCustomObject]@{
               Name = $file.Name
               Hash = [System.Bitconverter]::ToString([System.Security.Cryptography.HashAlgorithm]::Create('SHA1').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($file[0].Name))) }
            }   

        }
    }
}


#Pulls the event logs for all the most important events listed in the CSV file
function Get-ImportantEvent 
{ 
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [PSCustomObject]
        $EventList,

        [DateTime]
        $BeginTime,

        [DateTime]
        $EndTime,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($event in $using:EventList) {
                 Get-WinEvent -FilterHashtable @{ LogName = $event.Event_Log; StartTime=$using:BeginTime; EndTime=$using:EndTime; Id=$event.ID} 
                    }
        }
    }
}


function Group-Event 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        $EventRecord,

        [PSCustomObject]
        $EventList
    )

   Process
   {
       $groupEvents = ($EventRecord | Group-Object -Property ID | Sort-Object -Property Count -Descending)

       $groupEvents = foreach ($event in $groupEvents) {
        
            [pscustomObject]@{
            Count = $event.Count
            ID = $event.Name
            Description = ($eventList | Where-Object {$_.ID -eq $event.Name}).Description
            }

          }
    
        return $groupEvents
   }   
}

#Function taken from https://github.com/davehull/Kansa
function Get-Prefetch 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {   
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 

            Switch -Regex ($pfconf) {
                "[1-3]" {
                    $o = "" | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
                    ls $env:windir\Prefetch\*.pf | % {
                        $o.FullName = $_.FullName;
                        $o.CreationTimeUtc = Get-Date($_.CreationTimeUtc) -format o;
                        $o.LastAccesstimeUtc = Get-Date($_.LastAccessTimeUtc) -format o;
                        $o.LastWriteTimeUtc = Get-Date($_.LastWriteTimeUtc) -format o;
                        $o }
                         }
            default {
                Write-Output "Prefetch not enabled on ${env:COMPUTERNAME}."
                    }
            }
        } 

    }
}


function Get-RegistryIOC 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [PSCustomObject]
        $RegList,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($key in $using:RegList.Key)
                {
                   if (Get-ItemProperty -Path $key) {
                        $Content = Get-ItemProperty -Path $key
                        [PSCustomObject]@{ 
                        Key             = $key
                        IOC             = ($using:RegList | Where {$_.Key -eq $key}).IOC 
                        Data            = $Content.Data
                        Generation      = $Content.Generation
                        DependOnService = $Content.DependOnService
                        Description     = $Content.Description
                        DisplayName     = $Content.DisplayName
                        ImagePath       = $Content.ImagePath
                        Content         = $Content }
                   }
                }
        }
              
                            
    }   
}


<#Function created frome code taken from SANS whitepaper "Creating an Active Defense Powershell Framework" Author Kyle Snihur
This function can be usefull for creating a software map for normal application installs on a network.  You could use this in combination with
a Group-Object to determine anomolies #>

function Get-Software 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )

   Process
   {
       $Software = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\ `
       CurrentVersion\Uninstall\*" | Select DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString,InstallLocation

       $Software += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
       | Select DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString,InstallLocation

       $Software = $Software | Where-Object {[string]::IsNullOrWhiteSpace($_.displayname) -eq $false} `
       | Select-Object @{name="ComputerName";expression={$env:COMPUTERNAME}}, * | Sort-Object DisplayName

       $Software
    }
}

function Get-USB 
{ 
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $USBSTOR = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -Recurse -Force
            $USB     = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -Recurse -Force
            $PlugandPlay = if(Test-Path 'C:\Windows\inf\setupapi.dev.log') {
                    Get-Content 'C:\Windows\inf\setupapi.dev.log'
                    } else { Get-Content 'C:\Windows\inf\setupapi.log' }

            [PSCustomObject]@{
                                USBSTOR = $USBSTOR
                                USB     = $USB
                                PlugandPlay = $PlugandPlay
                             }
        }
    }
}


function Get-NamedPipe 
{ 
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        $namedPipes = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            [System.IO.Directory]::GetFiles("\\.\\pipe\\")
        }

        foreach ($pipe in $namedPipes)
        {
            [PSCustomObject]@{
                                Name = $pipe
                                PSComputerName = $pipe.PSComputerName
                             }
        }

    }
}


<#Event Form to ask user what the date range is for pulling logs and lets them select
a file containing the event properties that they want to query for #>

function Get-EventForm() {

$eventBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }

$inputXML = @"
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:HuntHome"
        mc:Ignorable="d"
        Title="Events" Height="261.885" Width="548.257">
    <Grid Margin="0,-12,2,5">
        <Grid.RowDefinitions>
            <RowDefinition Height="13*"/>
            <RowDefinition Height="200*"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="3*"/>
            <ColumnDefinition Width="16*"/>
            <ColumnDefinition Width="533*"/>
            <ColumnDefinition Width="7*"/>
            <ColumnDefinition/>
            <ColumnDefinition Width="7*"/>
        </Grid.ColumnDefinitions>
        <Button Content="Choose File" Name ="eventbrowseBtn" HorizontalAlignment="Left" Height="25" Margin="14,45,0,0" VerticalAlignment="Top" Width="81" Grid.Row="1" Grid.Column="2"/>
        <TextBox Name="eventTxt" HorizontalAlignment="Left" Height="25" Margin="105,45,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="392" Grid.Column="2" Grid.Row="1"/>
        <Label Content="Select the CSV file containing the events you want to query" FontWeight="SemiBold" HorizontalAlignment="Left" Height="32" Margin="7,13,0,0" VerticalAlignment="Top" Width="335" Grid.Row="1" Grid.Column="2"/>
        <Button Content="Save" Name="eventSaveButton" HorizontalAlignment="Left" Height="33" Margin="179,165,0,0" VerticalAlignment="Top" Width="99" Grid.Column="2" Grid.Row="1" RenderTransformOrigin="0.881,0.311"/>
        <Label FontWeight="Bold">Application Options</Label>
        <DatePicker Name="startDate" Grid.Column="2" HorizontalAlignment="Left" Height="27" Margin="76,105,0,0" Grid.Row="1" VerticalAlignment="Top" Width="105" RenderTransformOrigin="0.835,0.26"/>
        <Label Content="Start Date:" Grid.Column="2" HorizontalAlignment="Left" Height="27" Margin="10,105,0,0" Grid.Row="1" VerticalAlignment="Top" Width="66"/>
        <DatePicker x:Name="endDate" Grid.Column="2" HorizontalAlignment="Left" Height="27" Margin="280,105,0,0" Grid.Row="1" VerticalAlignment="Top" Width="105" RenderTransformOrigin="0.835,0.26"/>
        <Label Content="End Date:" Grid.Column="2" HorizontalAlignment="Left" Height="27" Margin="214,105,0,0" Grid.Row="1" VerticalAlignment="Top" Width="66"/>
    </Grid>
</Window>
"@

$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N",'N' -replace '^<Win.*', '<Window'
[XML]$XAML = $inputXML

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)

try {
    $window = [Windows.Markup.XamlReader]::Load( $reader )
    } catch {
        Write-Warning $_.Exception
        throw
    }

    #Create variables based on form control names.
    #Variable will be named as ;var<control name>'

    $xaml.SelectNodes("//*[@Name]") | ForEach-Object {
        #"Trying item $($_.Name)"
        try {
                Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction Stop
            } catch {
                throw
            }
    }
    
    #Event CSV File Location
    $var_eventbrowseBtn.Add_Click( {$eventBrowser.ShowDialog()
    $var_eventTxt.Text = $eventBrowser.FileName} )

     
    #save global variable for events.csv file location to be used on main form
    $var_eventSaveButton.Add_Click({
           
        $Script:eventsHash = [PSCustomObject]@{
            StartDate = $var_startDate.SelectedDate
            EndDate   = $var_endDate.SelectedDate
            Location  = $var_eventTxt.Text
            }
       
        $window.close()})     
    
    
    #Must be last line in script
    $Null = $window.ShowDialog()

    return $Script:eventsHash
    
    }


function Get-RegIOCForm() {

$regBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }

$inputXML = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:HuntHome"
        mc:Ignorable="d"
        Title="Evidence of Attack Tools" Height="189.959" Width="548.257">
    <Grid Margin="0,-12,2,5">
        <Grid.RowDefinitions>
            <RowDefinition Height="13*"/>
            <RowDefinition Height="200*"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="3*"/>
            <ColumnDefinition Width="16*"/>
            <ColumnDefinition Width="533*"/>
            <ColumnDefinition Width="7*"/>
            <ColumnDefinition/>
            <ColumnDefinition Width="7*"/>
        </Grid.ColumnDefinitions>
        <Button Content="Choose File" Name ="regiocbrowseBtn" HorizontalAlignment="Left" Height="25" Margin="14,45,0,0" VerticalAlignment="Top" Width="81" Grid.Row="1" Grid.Column="2"/>
        <TextBox Name="regTxt" HorizontalAlignment="Left" Height="25" Margin="105,45,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="392" Grid.Column="2" Grid.Row="1"/>
        <Label Content="Select the CSV file containing the registry keys and associated tools" FontWeight="SemiBold" HorizontalAlignment="Left" Height="32" Margin="7,13,0,0" VerticalAlignment="Top" Width="392" Grid.Row="1" Grid.Column="2"/>
        <Button Content="Save" Name="regSaveButton" HorizontalAlignment="Left" Height="33" Margin="194,102,0,0" VerticalAlignment="Top" Width="99" Grid.Column="2" Grid.Row="1" RenderTransformOrigin="0.881,0.311"/>
        <Label FontWeight="Bold">Application Options</Label>
    </Grid>
</Window>
"@

$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N",'N' -replace '^<Win.*', '<Window'
[XML]$XAML = $inputXML

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)

try {
    $window = [Windows.Markup.XamlReader]::Load( $reader )
    } catch {
        Write-Warning $_.Exception
        throw
    }

    #Create variables based on form control names.
    #Variable will be named as ;var<control name>'

    $xaml.SelectNodes("//*[@Name]") | ForEach-Object {
        #"Trying item $($_.Name)"
        try {
                Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction Stop
            } catch {
                throw
            }
    }

    $var_regiocbrowseBtn.Add_Click( {$regBrowser.ShowDialog()
    $var_regTxt.Text = $regBrowser.FileName} )

     
    $var_regSaveButton.Add_Click({$window.close()})     

    $Null = $window.ShowDialog()

    return $var_regTxt.Text
}

function Get-MainForm() {
$targBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }

$inputXML = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:HuntHome"
        mc:Ignorable="d"
        Title="Silent Hunter" Height="450" Width="603.586">
    <Grid Margin="0,-12,31,5">
        <Grid.RowDefinitions>
            <RowDefinition Height="44*"/>
            <RowDefinition Height="169*"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="3*"/>
            <ColumnDefinition Width="16*"/>
            <ColumnDefinition Width="538*"/>
            <ColumnDefinition Width="0*"/>
            <ColumnDefinition Width="8*"/>
            <ColumnDefinition Width="0*"/>
        </Grid.ColumnDefinitions>
        <Button Content="Choose File" Name ="browse1Btn" HorizontalAlignment="Left" Height="25" Margin="12,42,0,0" VerticalAlignment="Top" Width="81" Grid.Row="1" Grid.Column="2"/>
        <TextBox Name="targTxt" HorizontalAlignment="Left" Height="25" Margin="103,42,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="425" Grid.Column="2" Grid.Row="1"/>
        <Label Content="Select a CSV or Text file or enter your targets" FontWeight="SemiBold" HorizontalAlignment="Left" Height="32" Margin="3,10,0,0" VerticalAlignment="Top" Width="356" Grid.Row="1" Grid.Column="2"/>
        <Button Content="Run Script" Name="runButton" HorizontalAlignment="Left" Height="33" Margin="205,287,0,0" VerticalAlignment="Top" Width="154" Grid.Column="2" Grid.Row="1" RenderTransformOrigin="0.881,0.311"/>
        <Label Content="Username:" HorizontalAlignment="Left" Height="25" Margin="7,55,0,0" VerticalAlignment="Top" Width="76" Grid.Column="2"/>
        <TextBox Name="userTxt" HorizontalAlignment="Left" Height="23" Margin="76,55,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="186" Grid.Column="2"/>
        <Label Content="Password:" HorizontalAlignment="Left" Height="23" Margin="275,54,0,0" VerticalAlignment="Top" Width="62" Grid.Column="2" RenderTransformOrigin="1.068,0.086"/>
        <PasswordBox Name="passTxt" HorizontalAlignment="Left" VerticalAlignment="Top" Width="186" Grid.Column="2" Margin="342,55,0,0" Height="23"/>
        <Label Content="Enter the credentials" FontWeight="SemiBold" HorizontalAlignment="Left" Height="26" Margin="0,23,0,0" VerticalAlignment="Top" Width="129" Grid.Column="2"/>
        <Label FontWeight="Bold">Application Options</Label>
        <Label Content="Select the information you want to gather" FontWeight="SemiBold" HorizontalAlignment="Left" Height="32" Margin="3,82,0,0" VerticalAlignment="Top" Width="242" Grid.Row="1" Grid.Column="2"/>
        <CheckBox Content="Processes" Name="processCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="12,119,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="71"/>
        <CheckBox Content="Services" Name="serviceCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="12,148,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="62"/>
        <CheckBox Content="System Info" Name="systemCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="12,177,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="82"/>
        <CheckBox Content="Connections" Name="connectCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="12,206,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="86"/>
        <CheckBox Content="User Info" Name="userCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="12,235,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="68"/>
        <CheckBox Content="Group Info" Name="groupCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="127,119,0,0" Grid.Row="1" VerticalAlignment="Top" RenderTransformOrigin="-0.135,1.061" Height="15" Width="77"/>
        <CheckBox Content="Scheduled Tasks" Name="schtaskCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="127,148,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="106"/>
        <CheckBox Content="Autoruns" Name="autorunCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="127,177,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="68"/>
        <CheckBox Content="Tool Evidence" Name="toolCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="262,235,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="92"/>
        <CheckBox Content="Firewall Rules" Name="firewallCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="127,206,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="91"/>
        <CheckBox Content="Directory Walk" Name="dirwalkCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="262,119,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="97"/>
        <CheckBox Content="Hash Baseline" Name="hashCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="262,148,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="93"/>
        <CheckBox Content="Event Logs" Name="eventCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="262,177,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="77"/>
        <CheckBox Content="Prefetch" Name="prefetchCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="262,206,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="64"/>
        <CheckBox Content="Shares" Name="sharesCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="127,235,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="55"/>
        <CheckBox Content="Software" x:Name="softwareCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="395,119,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="92"/>
        <CheckBox Content="USB Usage" Name="usbCheck" Grid.Column="2" HorizontalAlignment="Left" Margin="395,148,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="92"/>
        <CheckBox Content="Named Pipes" Name="namedPipes" Grid.Column="2" HorizontalAlignment="Left" Margin="395,177,0,0" Grid.Row="1" VerticalAlignment="Top" Height="15" Width="92"/>
    </Grid>
</Window>
"@

$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N",'N' -replace '^<Win.*', '<Window'
[XML]$XAML = $inputXML

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)

try {
    $window = [Windows.Markup.XamlReader]::Load( $reader )
    } catch {
        Write-Warning $_.Exception
        throw
    }

    #Create variables based on form control names.
    #Variable will be named as ;var<control name>'

    $xaml.SelectNodes("//*[@Name]") | ForEach-Object {
        #"Trying item $($_.Name)"
        try {
                Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction Stop
            } catch {
                throw
            }
    }
    

    #Targets and determine what file type to use
    $var_browse1Btn.Add_Click( {
        $targBrowser.ShowDialog()
        $path = $targBrowser.FileName
        $extension = ($path[($path.Length - 3)..$path.Length]) -join ""
        #CSV file handler
        if($extension -eq "csv") {
            
            $importTargs = Import-Csv -Path $targBrowser.FileName -Header "Hosts"

            $targString = ''
            for($i=0;$i -lt ($importTargs.Hosts.Length); $i++) {
    
                if($i -lt ($importTargs.Hosts.Length - 1)) {
                    $targString += ($importTargs.Hosts[$i].toString() + ",")
                    } else {
                        $targString += $importTargs.Hosts[$i].ToString()
                     }
             }
             $var_targTxt.Text = $targString
            #txt file handler     
            } elseif($extension -eq "txt") {
                $var_targTxt.Text = Get-Content -Path $path
                } else {
                    $targBrowser.Dispose()
                    }
        })
    
    #Determine which scripts to run based on check boxes
    $var_runButton.Add_Click({
        
        #Create output folder
        $outputFolder = [string]::Concat($env:HOMEDRIVE,$env:HOMEPATH,'\Desktop\Output\')
        if(!(Test-Path $outputFolder)) {
            New-Item -Path $outputFolder -ItemType Directory
        }

        #Test if BaselineXML file already exists
        $xmlExists = Test-Path ($outputFolder + "BaselineInfo.xml")

        #Import existing XML file
        if($xmlExists) {
            $BaselineInfo = Import-Clixml -Path ($outputFolder + "BaselineInfo.xml")
            } else {
                $BaselineInfo = [PSCustomObject] @{                     
            Processes           = ''
            Services            = ''
            SystemInfo          = ''
            Connections         = ''
            Users               = ''
            LoggedOnUsers       = ''
            Groups              = ''
            GroupMembers        = ''
            SchTasks            = ''
            Autoruns            = ''
            Firewall            = ''
            Shares              = ''
            Dirwalk             = ''
            HashBaseline        = ''
            Events              = ''
            GroupedEvents       = ''
            Prefetch            = ''
            ToolEvidence        = ''
            Software            = ''
            USB                 = ''
            NamedPipes          = ''
            } }

        #Create creds
        $Username = $var_userTxt.Text
        $Password = $var_passTxt.SecurePassword
        [PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Password
        
        #Set targets and remove spaces and create array
        $targets = $var_targTxt.Text.Split(",") -replace '\s+', ''
            

    #----------------------------Progress Bar-------------------------------------------------------------------------
        Add-Type -assembly System.Windows.Forms

	## -- Create The Progress-Bar
	$ObjForm = New-Object System.Windows.Forms.Form
	$ObjForm.Text = "Baseline Progress"
	$ObjForm.Height = 100
	$ObjForm.Width = 500
	$ObjForm.BackColor = "White"

	$ObjForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
	$ObjForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

	## -- Create The Label
	$ObjLabel = New-Object System.Windows.Forms.Label
	$ObjLabel.Text = "Starting. Please wait ... "
	$ObjLabel.Left = 5
	$ObjLabel.Top = 10
	$ObjLabel.Width = 500 - 20
	$ObjLabel.Height = 15
	$ObjLabel.Font = "Tahoma"
	## -- Add the label to the Form
	$ObjForm.Controls.Add($ObjLabel)

	$PB = New-Object System.Windows.Forms.ProgressBar
	$PB.Name = "PowerShellProgressBar"
	$PB.Value = 0
	$PB.Style="Continuous"

	$System_Drawing_Size = New-Object System.Drawing.Size
	$System_Drawing_Size.Width = 500 - 40
	$System_Drawing_Size.Height = 20
	$PB.Size = $System_Drawing_Size
	$PB.Left = 5
	$PB.Top = 40
	$ObjForm.Controls.Add($PB)

	## -- Show the Progress-Bar and Start The PowerShell Script
	$ObjForm.Show() | Out-Null
	$ObjForm.Focus() | Out-NUll
	$ObjLabel.Text = "Starting. Please wait ... "
	$ObjForm.Refresh()

	Start-Sleep -Seconds 1
#---------------------------------------------------------------------------------------------------------
  #Start progress bar
    $continue = $true
	While ($continue) {
        $ObjLabel.Text = "Enumerating machines in target file"

        #process check box
        if ($var_processCheck.IsChecked)
        {
           $processes = Get-WmiProcess -ComputerName $targets -Credential $creds
           $processes | Export-CSV -Path ($outputFolder + "process.csv") -NoTypeInformation
           $BaselineInfo.Processes = $processes
        }

        $PB.Value = 6
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #service check box
        if ($var_serviceCheck.IsChecked)
        {
           $services = Get-WmiService -ComputerName $targets -Credential $creds
           $services | Export-CSV -Path ($outputFolder + "service.csv") -NoTypeInformation
           $BaselineInfo.Services = $services
        }

        $PB.Value = 12
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #systeminfo check box
        if ($var_systemCheck.IsChecked)
        {
           $systeminfo = Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {Get-ComputerInfo}
           $systeminfo | Export-CSV -Path ($outputFolder + "systeminfo.csv") -NoTypeInformation
           $BaselineInfo.SystemInfo = $systeminfo
        }

        $PB.Value = 18
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150


        #connections check box
        if ($var_connectCheck.IsChecked)
        {
           $connections = Get-Connection -ComputerName $targets -Credential $creds
           $connections | Export-CSV -Path ($outputFolder + "connections.csv") -NoTypeInformation
           $BaselineInfo.Connections = $connections
        }

        $PB.Value = 24
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #user info check box
        if ($var_userCheck.IsChecked)
        {
           $users = Get-LUser -ComputerName $targets -Credential $creds
           $LoggedOnUsers = Get-LoggedOnUser -ComputerName $targets -Credential $creds
           $users | Export-CSV -Path ($outputFolder + "users.csv") -NoTypeInformation
           $LoggedOnUsers | Export-CSV -Path ($outputFolder + "loggedonusers.csv") -NoTypeInformation
           $BaselineInfo.Users = $users
           $BaselineInfo.LoggedOnUsers = $LoggedOnUsers

        }

        $PB.Value = 30
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #group info check box
        if ($var_groupCheck.IsChecked)
        {
           $groups = Get-LGroup -ComputerName $targets -Credential $creds
           $groupMembers = Get-LGroupMembers -ComputerName $targets -Credential $creds
           $groups | Export-CSV -Path ($outputFolder + "groups.csv") -NoTypeInformation
           $groupMembers | Export-CSV -Path ($outputFolder + "groupmembers.csv") -NoTypeInformation
           $BaselineInfo.Groups = $groups
           $BaselineInfo.GroupMembers = $groupMembers

        }

        
        $PB.Value = 36
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150


        #sch tasks check box
        if ($var_schtaskCheck.IsChecked)
        {
           $schtasks = Get-SchTask -ComputerName $targets -Credential $creds
           $schtasks | Export-CSV -Path ($outputFolder + "schtasks.csv") -NoTypeInformation
           $BaselineInfo.SchTasks = $schtasks

        }

        $PB.Value = 42
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #autoruns check box
        if ($var_autorunCheck.IsChecked)
        {
           $autoruns = Get-Autoruns -ComputerName $targets -Credential $creds
           $autoruns | Export-CSV -Path ($outputFolder + "autoruns.csv") -NoTypeInformation
           $BaselineInfo.Autoruns = $autoruns

        }

        $PB.Value = 48
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #firewall check box
        if ($var_firewallCheck.IsChecked)
        {
           $firewall = Survey-Firewall -ComputerName $targets -Credential $creds
           $firewall | Export-CSV -Path ($outputFolder + "firewall.csv") -NoTypeInformation
           $BaselineInfo.Firewall = $firewall
        }

        $PB.Value = 54
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #shares check box
        if ($var_sharesCheck.IsChecked)
        {
           $shares = Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {Get-WmiObject -ClassName Win32_Share}
           $shares | Export-CSV -Path ($outputFolder + "shares.csv") -NoTypeInformation
           $BaselineInfo.Shares = $shares

        }

        $PB.Value = 60
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150


        #dirwalk check box
        if ($var_dirwalkCheck.IsChecked)
        {
           $dirwalk = Get-DirWalk -ComputerName $targets -Credential $creds -path 'C:\'
           $dirwalk | Export-CSV -Path ($outputFolder + "dirwalk.csv") -NoTypeInformation
           $BaselineInfo.DirWalk = $dirwalk

        }

        $PB.Value = 66
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150


        #hash baseline check box
        if ($var_hashCheck.IsChecked)
        {
           $hashbaseline = Get-DirWalkHash -ComputerName $targets -Credential $creds -path 'C:\'
           $hashbaseline | Export-CSV -Path ($outputFolder + "hashbaseline.csv") -NoTypeInformation
           $BaselineInfo.HashBaseline = $hashbaseline

        }

        $PB.Value = 72
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150


        #eventlog check box
        if ($var_eventCheck.IsChecked)
        {
           
           $eventQuery = Get-EventForm
           [DateTime]$startDate  = Get-Date -Date $eventQuery.StartDate
           [DateTime]$endDate    = Get-Date -Date $eventQuery.EndDate
           $events               = Get-ImportantEvent -ComputerName $targets -Credential $creds -EventList (Import-Csv -Path $eventQuery.Location) -BeginTime $startDate -EndTime $endDate
           $groupEvents          = Group-Event -EventRecord $events -EventList (Import-Csv -Path $eventQuery.Location)
           $events | Export-CSV -Path ($outputFolder + "events.csv") -NoTypeInformation
           $groupEvents | Export-CSV -Path ($outputFolder + "GroupedEvents.txt") -NoTypeInformation
           $BaselineInfo.Events = $events
           $BaselineInfo.GroupedEvents = $groupEvents

        }

        $PB.Value = 78
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #prefetch check box
        if ($var_prefetchCheck.IsChecked)
        {
           $prefetch = Get-Prefetch -ComputerName $targets -Credential $creds
           $prefetch | Export-CSV -Path ($outputFolder + "prefetch.csv") -NoTypeInformation
           $BaselineInfo.Prefetch = $prefetch

        }

        $PB.Value = 84
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150


        #tool check box
        if ($var_toolCheck.IsChecked)
        {
           $regIOC = Import-Csv -Path (Get-RegIOCForm)
           $tools  = Get-RegistryIOC -ComputerName $targets -Credential $creds -RegList $regIOC
           $tools | Export-CSV -Path ($outputFolder + "tools.csv") -NoTypeInformation
           $BaselineInfo.ToolEvidence = $tools

        }

        $PB.Value = 90
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #software check box
        if ($var_softwareCheck.IsChecked)
        {
           $software = Get-Software -ComputerName $targets -Credential $creds
           $BaselineInfo.Software = $software
           
        }

        $PB.Value = 94
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #USB check box
        if ($var_usbCheck.IsChecked)
        {
           $usb = Get-USB -ComputerName $targets -Credential $creds
           $BaselineInfo.USB = $usb
           
        } 

        $PB.Value = 96
        $ObjForm.Refresh()
		Start-Sleep -Milliseconds 150

        #Named Pipes check box
        if ($var_namedPipes.IsChecked)
        {
           $namedPipes = Get-NamedPipe -ComputerName $targets -Credential $creds
           $BaselineInfo.NamedPipes = $namedPipes
           $namedPipes | Export-Csv -Path ($outputFolder + "namedpipes.csv") -NoTypeInformation
           
        } 


        $BaselineInfo | Export-Clixml -Path ($outputFolder + "BaselineInfo.xml")

        
        $ObjLabel.Text = ("The files are located in " + $outputFolder)
        Start-Sleep -Milliseconds 2000

        $PB.Value = 100
        $ObjForm.Refresh()
  
        $continue = $false
        }
        $ObjForm.Close()

        $window.close()
        })

    #Must be last line in script
    $Null = $window.ShowDialog()
}


Get-MainForm