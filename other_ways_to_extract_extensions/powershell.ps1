# Get-ChromeExtensions
# Prints out JSON outputs as text output, next step will be modifying as function output
# in order to be used with CrowdStrike Response API and our python scripts

######################

$AllUserFolders = Get-ChildItem -Path "C:\Users"
ForEach ($UserFolder in $AllUserFolders){
    if (Test-Path -Path "$($UserFolder.FullName)\AppData\Local\Google\Chrome\User Data\Default\Extensions")
    {
        $AllExtensionsFolders = Get-ChildItem -Path "$($UserFolder.FullName)\AppData\Local\Google\Chrome\User Data\Default\Extensions"
        ForEach ($ExtensionFolder in $AllExtensionsFolders){
            $VersionFolders = Get-ChildItem -Path "$($ExtensionFolder.FullName)"
            Foreach ($VersionFolder in $VersionFolders) {
                
                # Check "manifest" and "messages" for the extension name
                $json = Get-Content -Raw -Path "$($VersionFolder.FullName)\manifest.json" | ConvertFrom-Json
                $ExtensionName = $json.name

                if( $ExtensionName -like "*MSG*" ) {
                    if( Test-Path -Path "$($VersionFolder.FullName)\_locales\en\messages.json" ) {
                        $json = Get-Content -Raw -Path "$($VersionFolder.FullName)\_locales\en\messages.json" | ConvertFrom-Json
                        $ExtensionName = $json.appName.message
                        if(!$ExtensionName) {
                            $ExtensionName = $json.extName.message
                        }
                        if(!$ExtensionName) {
                            $ExtensionName = $json.app_name.message
                        }
                    }
                    
                    if( Test-Path -Path "$($VersionFolder.FullName)\_locales\en_US\messages.json" ) {
                        $json = Get-Content -Raw -Path "$($VersionFolder.FullName)\_locales\en_US\messages.json" | ConvertFrom-Json
                        $ExtensionName = $json.appName.message
                        if(!$ExtensionName) {
                            $ExtensionName = $json.extName.message
                        }
                        if(!$ExtensionName) {
                            $ExtensionName = $json.app_name.message
                        }
                    }
                }
                # Generating output as JSON, including hostname & username
                @{Host=$env:computername;User=$UserFolder.Name;ExtensionID=$ExtensionFolder.Name;ExtensionName=$ExtensionName;Version=$VersionFolder.Name} | ConvertTo-Json -Compress
            }
        }      
    }
}
