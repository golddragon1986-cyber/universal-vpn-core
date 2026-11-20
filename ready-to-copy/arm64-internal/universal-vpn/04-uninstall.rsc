{
# Remove installer-owned resources, including incomplete USB and internal installs.
:local scopes {"uvpn-main";"uvpn-usb";"uvpn-int"}
:local bases {"universal-vpn"=true;"flash/universal-vpn"=true}
:foreach disk in=[/disk find where mount-filesystem=yes] do={
    :local mount [/disk get $disk mount-point]
    :if ([:len $mount] > 0) do={
        :local base ($mount . "/universal-vpn")
        :set ($bases->$base) true
    }
}

# Check for shared interfaces, mounts or storage before removing anything.
:foreach id in=[/container find] do={
    :local veth [/container get $id interface]
    :local name [/container get $id name]
    :local root [:tostr [/container get $id root-dir]]
    :if ([:pick $root 0 1] = "/") do={ :set root [:pick $root 1 [:len $root]] }
    :local owned false
    :local reserved false
    :foreach scope in=$scopes do={
        :if ($veth = ($scope . "-veth")) do={ :set reserved true }
    }
    :if ($name = "universal-vpn-core" && $reserved) do={ :set owned true }
    :if (!$owned && $reserved) do={ :error "Another container uses an installer interface" }
    :if (!$owned) do={
        :foreach base,present in=$bases do={
            :local rootDir ($base . "/rootfs")
            :local dataDir ($base . "/data")
            :if ($root = $rootDir || $root = $dataDir || [:pick $root 0 ([:len $rootDir] + 1)] = ($rootDir . "/") || [:pick $root 0 ([:len $dataDir] + 1)] = ($dataDir . "/")) do={
                :error ("Another container uses storage in " . $base)
            }
        }
        :foreach mountList in=[/container get $id mountlists] do={
            :foreach scope in=$scopes do={
                :if ($mountList = $scope) do={ :error "Another container uses an installer mount list" }
            }
        }
    }
}
:foreach scope in=$scopes do={
    :local bridgeName ($scope . "-br")
    :local vethName ($scope . "-veth")
    :if ([:len [/interface bridge find where name=$bridgeName]] > 0) do={
        :foreach port in=[/interface bridge port find where bridge=$bridgeName] do={
            :if ([/interface bridge port get $port interface] != $vethName) do={
            :error ("Other ports are attached to " . $bridgeName)
            }
        }
    }
}
:foreach id in=[/container mounts find] do={
    :local list [/container mounts get $id list]
    :local source [:tostr [/container mounts get $id src]]
    :if ([:pick $source 0 1] = "/") do={ :set source [:pick $source 1 [:len $source]] }
    :local owned false
    :foreach scope in=$scopes do={ :if ($list = $scope) do={ :set owned true } }
    :if (!$owned) do={
        :foreach base,present in=$bases do={
            :local rootDir ($base . "/rootfs")
            :local dataDir ($base . "/data")
            :if ($source = $base || $source = $rootDir || $source = $dataDir || [:pick $source 0 ([:len $rootDir] + 1)] = ($rootDir . "/") || [:pick $source 0 ([:len $dataDir] + 1)] = ($dataDir . "/")) do={
                :error ("Another mount uses storage in " . $base)
            }
        }
    }
}

:foreach scope in=$scopes do={
    :local tag ($scope . ": routing")
    :foreach id in=[/ip firewall nat find where comment=$tag] do={ /ip firewall nat remove $id }
    :foreach id in=[/ip firewall filter find where comment=$tag] do={ /ip firewall filter remove $id }
    :foreach id in=[/ip route find where comment=$tag] do={ /ip route remove $id }
}
:local stopped false
:foreach scope in=$scopes do={
    :local vethName ($scope . "-veth")
    :foreach id in=[/container find where name="universal-vpn-core" and interface=$vethName] do={
        :onerror stopError in={ /container stop $id } do={ :put ("Stop: " . $stopError) }
        :set stopped true
    }
}
:if ($stopped) do={ :delay 15s }
:foreach scope in=$scopes do={
    :local vethName ($scope . "-veth")
    :foreach id in=[/container find where name="universal-vpn-core" and interface=$vethName] do={ /container remove $id }
    :local attempts 0
    :while (([:len [/container find where name="universal-vpn-core" and interface=$vethName]] > 0) && ($attempts < 60)) do={
        :delay 1s
        :set attempts ($attempts + 1)
    }
    :if ([:len [/container find where name="universal-vpn-core" and interface=$vethName]] > 0) do={
        :error ("Container removal still pending on " . $vethName)
    }
    :local tag ($scope . ": base")
    :local bridgeName ($scope . "-br")
    :local clients ($scope . "-lan")
    :foreach id in=[/ip firewall nat find where comment=$tag] do={ /ip firewall nat remove $id }
    :foreach id in=[/ip firewall filter find where comment=$tag] do={ /ip firewall filter remove $id }
    :foreach id in=[/ip firewall address-list find where list=$clients and comment=$tag] do={ /ip firewall address-list remove $id }
    :foreach id in=[/ip address find where interface=$bridgeName and address="172.31.41.1/24"] do={ /ip address remove $id }
    :foreach id in=[/container mounts find where list=$scope] do={ /container mounts remove $id }
    :foreach id in=[/container envs find where list=$scope] do={ /container envs remove $id }
    :foreach id in=[/interface bridge port find where bridge=$bridgeName and interface=$vethName] do={ /interface bridge port remove $id }
    :foreach id in=[/interface bridge find where name=$bridgeName] do={ /interface bridge remove $id }
    :foreach id in=[/interface veth find where name=$vethName] do={ /interface veth remove $id }
}

:foreach base,present in=$bases do={
    :local root ($base . "/rootfs")
    :local data ($base . "/data")
    :local marker ($base . "/universal-vpn.install-marker")
    :foreach id in=[/file find where (name=$root or name=$data) and (type="directory" or type="container store")] do={ /file remove $id }
    :if ([:len [/file find where name=$root or name=$data]] > 0) do={ :error ("Working files remain in " . $base) }
    :foreach id in=[/file find where name=$marker] do={ /file remove $id }
}
:put "Universal VPN removed. Release files retained."
}
