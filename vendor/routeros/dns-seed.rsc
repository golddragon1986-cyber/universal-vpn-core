# Read independent upstream DNS before creating the container.
:local blockedDns ",0.0.0.0,172.31.41.1,172.31.41.2,"
:foreach id in=[/ip address find] do={
    :local address [:tostr [/ip address get $id address]]
    :set blockedDns ($blockedDns . [:pick $address 0 [:find $address "/"]] . ",")
}
:local safeDns do={
    :local ip [:toip $value]
    :if ([:typeof $ip] != "ip") do={ :return false }
    :if ([:pick [:tostr $ip] 0 4] = "127." || $ip in 198.18.0.0/16) do={ :return false }
    :if ([:typeof [:find $blocked ("," . [:tostr $ip] . ",")]] != "nil") do={ :return false }
    :return true
}
:local routerDnsPrimary ""
:foreach kind in={"servers";"dynamic-servers"} do={
    :foreach address in=[/ip dns get $kind] do={
        :local value [:tostr $address]
        :if ([$safeDns value=$value blocked=$blockedDns] = true) do={
            :if ([:typeof [:find ("," . $routerDnsPrimary . ",") ("," . $value . ",")]] = "nil") do={
                :if ([:len $routerDnsPrimary] > 0) do={ :set routerDnsPrimary ($routerDnsPrimary . ",") }
                :set routerDnsPrimary ($routerDnsPrimary . $value)
            }
        }
    }
}
:if ([:len $routerDnsPrimary] = 0) do={ :error "No independent upstream DNS in RouterOS; configure a DNS server outside this router and container" }
:local routerDnsMain [/ip dns get use-doh-server]
:if ([:len $routerDnsMain] > 0) do={
    :local end [:find $routerDnsMain "/" 8]
    :if ([:typeof $end] = "nil") do={ :set end [:len $routerDnsMain] }
    :local host [:pick $routerDnsMain 8 $end]
    :local port [:find $host ":"]
    :if ([:typeof $port] != "nil") do={ :set host [:pick $host 0 $port] }
    :if ([:typeof [:toip $host]] = "ip") do={
        :if ([$safeDns value=$host blocked=$blockedDns] != true) do={ :set routerDnsMain "" }
    } else={
        :if ($host = "localhost" || [:pick $host 0 1] = "[") do={ :set routerDnsMain "" } else={
            :foreach server in=[:toarray $routerDnsPrimary] do={
                :do {
                    :local resolved [:resolve domain-name=$host server=$server type=ipv4]
                    :if ([$safeDns value=$resolved blocked=$blockedDns] != true) do={ :set routerDnsMain "" }
                } on-error={}
            }
        }
    }
}
:if ([:len $routerDnsMain] = 0) do={ :set routerDnsMain $routerDnsPrimary }
