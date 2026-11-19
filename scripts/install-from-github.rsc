{
# Run once in a RouterOS terminal after enabling the container package and device mode.
:local tag "v0.31b.191126.1600"
:local repo "https://github.com/golddragon1986-cyber/universal-vpn-core/releases/download/"
:local arch [/system resource get architecture-name]
:local image "universal-vpn-core-armv7.tar"
:local required 268435456
:if ($arch = "arm64") do={ :set image "universal-vpn-core-arm64.tar"; :set required 335544320 } else={
    :if ($arch != "arm") do={ :error "Universal VPN Core requires RouterOS ARM or ARM64" }
}
:if ([/system device-mode get container] != true) do={ :error "Enable container device mode first" }
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
:if ([:len [/file find where name=$target]] > 0) do={ :error ("Target already exists: " . $target) }
/file add name=$target type=directory
:local base ($repo . $tag . "/")
:foreach name in={"01-install.rsc";"02-enable-routing.rsc";"03-disable-routing.rsc";"04-uninstall.rsc"} do={
    :do {
        /tool fetch url=($base . $name) dst-path=($target . "/" . $name) check-certificate=yes http-max-redirect-count=5
    } on-error={ :error ("Failed to download " . $name . "; check GitHub reachability and remove incomplete " . $target) }
}
:do {
    /tool fetch url=($base . $image) dst-path=($target . "/" . $image) check-certificate=yes http-max-redirect-count=5
} on-error={ :error ("Failed to download " . $image . "; check storage and remove incomplete " . $target) }
:if ([:len [/file find where name=($target . "/" . $image)]] != 1) do={ :error "Image download missing" }
:put ("Downloaded Universal VPN Core " . $tag . " to " . $target)
:put ("Review the installer, then run: /import file-name=\"" . $target . "/01-install.rsc\" verbose=yes dry-run")
:put ("To install: /import file-name=\"" . $target . "/01-install.rsc\"")
}
