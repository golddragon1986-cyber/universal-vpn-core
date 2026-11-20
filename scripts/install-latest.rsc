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
:put "Installing and extracting the container..."
/import file-name=($target . "/01-install.rsc")

:local instance [/container find where name="universal-vpn-core" and interface="uvpn-main-veth"]
:if ([:len $instance] != 1) do={ :error "Container installation did not create the expected instance" }
/container start $instance
:put "Waiting for the panel to become available..."
:local panelReady false
:local deadline ([/system resource get uptime] + 5m)
:while (!$panelReady && [/system resource get uptime] < $deadline) do={
    :delay 2s
    :do {
        :local probe [/tool fetch url="http://172.31.41.2:9091/" output=none as-value idle-timeout=5s]
        :if (($probe->"code") = 200) do={ :set panelReady true }
    } on-error={}
}
:if (!$panelReady) do={ :error "Container was installed and started, but the panel did not become ready; check /container print detail and /log print where topics~container before enabling client routing" }

:put "Checking container DNS..."
:local dnsReady false
:local dnsDeadline ([/system resource get uptime] + 1m)
:while (!$dnsReady && [/system resource get uptime] < $dnsDeadline) do={
    :do {
        :local answer [:resolve domain-name="example.com" server=172.31.41.2 type=ipv4]
        :if ([:typeof $answer] = "ip") do={ :set dnsReady true }
    } on-error={}
    :if (!$dnsReady) do={ :delay 2s }
}
:if (!$dnsReady) do={ :error "Container DNS did not answer; client DNS and routing were not enabled" }

:put "Enabling client DNS and Fake-IP routing..."
/import file-name=($target . "/02-enable-routing.rsc")
:if ([:len [/ip route find where dst-address="198.18.0.0/16" and gateway="172.31.41.2"]] != 1) do={ :error "Routing script finished but the Fake-IP route is missing" }
:if ([:len [/ip firewall nat find where comment="uvpn-main: routing" and protocol=udp and dst-port=53]] != 1 || [:len [/ip firewall nat find where comment="uvpn-main: routing" and protocol=tcp and dst-port=53]] != 1) do={ :error "Routing script finished but client DNS rules are missing" }

:put ("Universal VPN Core " . $tag . " installation complete")
:put ("Files: " . $target)
:put "Container: running, start on boot enabled"
:put "Container DNS: example.com resolved"
:put "Client DNS: TCP/UDP port 53 forwarded to 172.31.41.2"
:put "Fake-IP route: 198.18.0.0/16 via 172.31.41.2"
:put "Panel: http://172.31.41.2:9091/"
:put "Add your VPN profiles and subscriptions in the panel, then apply its configuration."
}
