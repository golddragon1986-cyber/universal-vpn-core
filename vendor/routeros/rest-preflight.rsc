:local restService [/ip service find where name="www-ssl"]
:if ([:len $restService] != 1) do={ :error "RouterOS HTTPS service unavailable" }
:if ([/ip service get $restService disabled] = false || [/ip service get $restService port] != 443 || [/ip service get $restService certificate] != "none") do={
    :error "www-ssl is already configured; cannot provision an isolated REST endpoint"
}
:local serviceAddresses ""
:onerror serviceFieldError in={
    :set serviceAddresses [/ip service get $restService "address"]
} do={
    :set serviceAddresses [/ip service get $restService "available-from"]
}
:if ([:len $serviceAddresses] > 0) do={ :error "www-ssl already has address restrictions; cannot provision REST" }
:if ([:len [/user find where name="uvpn-main-panel"]] > 0 || [:len [/user group find where name="uvpn-main-rest"]] > 0 || [:len [/certificate find where name="uvpn-main-ca" or name="uvpn-main-rest"]] > 0 || [:len [/routing table find where name="uvpn-main-direct"]] > 0 || [:len [/file find where name="uvpn-main-ca-export.crt"]] > 0) do={
    :error "REST resources already exist; run 04-uninstall first"
}
