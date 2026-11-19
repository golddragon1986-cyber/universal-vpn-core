{
# Download the latest Universal VPN Core release through GitHub's REST API.
# RouterOS 7.25.1 cannot parse the long signed redirect from release assets.
:local owner "golddragon1986-cyber"
:local repository "universal-vpn-core"
:local api ("https://api.github.com/repos/" . $owner . "/" . $repository . "/releases/latest")
:local assetApi ("https://api.github.com/repos/" . $owner . "/" . $repository . "/releases/assets/")
:local arch [/system resource get architecture-name]
:local image "universal-vpn-core-armv7.tar"
:local required 268435456
:if ($arch = "arm64") do={ :set image "universal-vpn-core-arm64.tar"; :set required 335544320 } else={
    :if ($arch != "arm") do={ :error "Universal VPN Core requires RouterOS ARM or ARM64" }
}
:if ([/system device-mode get container] != true) do={ :error "Enable container device mode first" }

# Fetch and parse the latest release manifest.
:local metadata
:do {
    :local response [/tool fetch url=$api output=user as-value check-certificate=yes]
    :set metadata [:deserialize ($response->"data") from=json]
} on-error={ :error "Could not read latest GitHub release metadata" }
:local tag ($metadata->"tag_name")
:if ([:len $tag] = 0) do={ :error "GitHub returned no latest release tag" }
:local assets ($metadata->"assets")

:local target ""
:local eligible 0
:foreach disk in=[/disk find where mount-filesystem=yes] do={
    :if ([/disk get $disk fs] = "ext4" && [/disk get $disk mount-read-only] = false && [/disk get $disk free] >= $required) do={
        :set target ([/disk get $disk mount-point] . "/universal-vpn")
        :set eligible ($eligible + 1)
    }
}
:if ($eligible > 1) do={ :error "More than one suitable ext4 disk; select a disk and use the manual installer" }
:if ($eligible = 0) do={
    :if ([/system resource get free-hdd-space] < $required) do={ :error "Insufficient storage; attach an ext4 disk" }
    :set target "universal-vpn"
    :if ([:len [/file find where name="flash"]] > 0) do={ :set target "flash/universal-vpn" }
}
:if ([:len [/file find where name=$target]] > 0) do={ :error ("Target already exists: " . $target . "; remove the incomplete folder before retrying") }
/file add name=$target type=directory

:foreach name in={"01-install.rsc";"02-enable-routing.rsc";"03-disable-routing.rsc";"04-uninstall.rsc";$image} do={
    :local assetId 0
    :local assetSize 0
    :foreach item in=$assets do={
        :if (($item->"name") = $name) do={
            :set assetId ($item->"id")
            :set assetSize ($item->"size")
        }
    }
    :if ($assetId = 0) do={ :error ("Latest GitHub release has no asset " . $name) }
    :if ($name = $image && $assetSize > $required) do={
        :local enoughSpace false
        :foreach disk in=[/disk find where mount-filesystem=yes] do={
            :if ([/disk get $disk fs] = "ext4" && [/disk get $disk mount-read-only] = false && [/disk get $disk free] >= ($assetSize + 16777216)) do={ :set enoughSpace true }
        }
        :if (!$enoughSpace && [/system resource get free-hdd-space] < ($assetSize + 16777216)) do={ :error "Insufficient free space for the selected release image" }
    }
    :local destination ($target . "/" . $name)
    :do {
        /tool fetch url=($assetApi . $assetId) http-header-field="Accept: application/octet-stream" dst-path=$destination check-certificate=yes
    } on-error={ :error ("GitHub API download failed for " . $name . "; remove incomplete folder " . $target . " before retrying") }
    :local fileId [/file find where name=$destination]
    :if ([:len $fileId] != 1) do={ :error ("Downloaded file is missing: " . $name) }
    :if ([/file get $fileId size] != $assetSize) do={ :error ("Downloaded size differs from GitHub release metadata: " . $name) }
}

:put ("Downloaded Universal VPN Core " . $tag . " to " . $target)
:put ("Review the installer, then run: /import file-name=\"" . $target . "/01-install.rsc\" verbose=yes dry-run")
:put ("To install: /import file-name=\"" . $target . "/01-install.rsc\"")
}
