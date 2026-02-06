#!/bin/bash
#
# NVD Package Matcher Library
#
# Purpose: Match installed software packages to CVEs in NVD
# Maps package names to CPE (Common Platform Enumeration) format
#
# Compatible with Bash 3.2+ (macOS default)

# Prevent direct execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly." >&2
    exit 1
fi

# Get CPE vendor and product for known packages
# Returns "vendor:product" or empty if unknown
# Usage: get_cpe_mapping "openssl"
get_cpe_mapping() {
    local package="$1"
    local normalized
    normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]' | sed 's/-bin$//; s/-dev$//; s/-libs$//')

    case "$normalized" in
        # ===========================================
        # Security Tools (20+)
        # ===========================================
        openssl|libssl)   echo "openssl:openssl" ;;
        openssh|ssh)      echo "openbsd:openssh" ;;
        gnupg|gpg)        echo "gnupg:gnupg" ;;
        clamav)           echo "clamav:clamav" ;;
        nmap)             echo "nmap:nmap" ;;
        wireshark|tshark) echo "wireshark:wireshark" ;;
        fail2ban)         echo "fail2ban:fail2ban" ;;
        lynis)            echo "cisofy:lynis" ;;
        snort)            echo "snort:snort" ;;
        suricata)         echo "oisf:suricata" ;;
        ossec)            echo "ossec:ossec" ;;
        tripwire)         echo "tripwire:tripwire" ;;
        aide)             echo "aide:aide" ;;
        rkhunter)         echo "rkhunter:rkhunter" ;;
        chkrootkit)       echo "chkrootkit:chkrootkit" ;;
        hashcat)          echo "hashcat:hashcat" ;;
        john|johntheripper) echo "openwall:john_the_ripper" ;;
        nessus)           echo "tenable:nessus" ;;
        burpsuite|burp)   echo "portswigger:burp_suite" ;;
        metasploit)       echo "rapid7:metasploit" ;;
        nikto)            echo "cirt:nikto" ;;
        sqlmap)           echo "sqlmap:sqlmap" ;;
        hydra)            echo "thc:hydra" ;;

        # ===========================================
        # Programming Languages & Runtimes (25+)
        # ===========================================
        python|python3|python2) echo "python:python" ;;
        node|nodejs)      echo "nodejs:node.js" ;;
        ruby)             echo "ruby-lang:ruby" ;;
        perl)             echo "perl:perl" ;;
        php)              echo "php:php" ;;
        go|golang)        echo "golang:go" ;;
        rust|rustc)       echo "rust-lang:rust" ;;
        java|openjdk)     echo "oracle:openjdk" ;;
        scala)            echo "scala-lang:scala" ;;
        kotlin)           echo "jetbrains:kotlin" ;;
        swift)            echo "apple:swift" ;;
        dotnet|.net)      echo "microsoft:.net" ;;
        mono)             echo "mono-project:mono" ;;
        erlang)           echo "erlang:erlang" ;;
        elixir)           echo "elixir-lang:elixir" ;;
        haskell|ghc)      echo "haskell:ghc" ;;
        lua)              echo "lua:lua" ;;
        r|r-lang)         echo "r-project:r" ;;
        julia)            echo "julialang:julia" ;;
        dart)             echo "dart:dart" ;;
        deno)             echo "deno:deno" ;;
        bun)              echo "oven-sh:bun" ;;
        zig)              echo "ziglang:zig" ;;
        clojure)          echo "clojure:clojure" ;;
        groovy)           echo "apache:groovy" ;;

        # ===========================================
        # Web Servers & Proxies (15+)
        # ===========================================
        nginx)            echo "nginx:nginx" ;;
        apache|httpd|apache2) echo "apache:http_server" ;;
        caddy)            echo "caddyserver:caddy" ;;
        lighttpd)         echo "lighttpd:lighttpd" ;;
        haproxy)          echo "haproxy:haproxy" ;;
        traefik)          echo "traefik:traefik" ;;
        envoy)            echo "envoyproxy:envoy" ;;
        tomcat)           echo "apache:tomcat" ;;
        jetty)            echo "eclipse:jetty" ;;
        gunicorn)         echo "gunicorn:gunicorn" ;;
        uwsgi)            echo "unbit:uwsgi" ;;
        varnish)          echo "varnish-software:varnish" ;;
        squid)            echo "squid-cache:squid" ;;
        pound)            echo "pound:pound" ;;
        cherokee)         echo "cherokee-project:cherokee" ;;

        # ===========================================
        # Databases (25+)
        # ===========================================
        postgresql|postgres) echo "postgresql:postgresql" ;;
        mysql)            echo "oracle:mysql" ;;
        mariadb)          echo "mariadb:mariadb" ;;
        mongodb)          echo "mongodb:mongodb" ;;
        redis)            echo "redis:redis" ;;
        sqlite|sqlite3)   echo "sqlite:sqlite" ;;
        elasticsearch)    echo "elastic:elasticsearch" ;;
        opensearch)       echo "amazon:opensearch" ;;
        cassandra)        echo "apache:cassandra" ;;
        couchdb)          echo "apache:couchdb" ;;
        couchbase)        echo "couchbase:couchbase_server" ;;
        neo4j)            echo "neo4j:neo4j" ;;
        influxdb)         echo "influxdata:influxdb" ;;
        timescaledb)      echo "timescale:timescaledb" ;;
        clickhouse)       echo "clickhouse:clickhouse" ;;
        cockroachdb|cockroach) echo "cockroachlabs:cockroachdb" ;;
        rethinkdb)        echo "rethinkdb:rethinkdb" ;;
        memcached)        echo "memcached:memcached" ;;
        etcd)             echo "etcd-io:etcd" ;;
        consul)           echo "hashicorp:consul" ;;
        zookeeper)        echo "apache:zookeeper" ;;
        arangodb)         echo "arangodb:arangodb" ;;
        firebird)         echo "firebird:firebird" ;;
        derby)            echo "apache:derby" ;;
        h2)               echo "h2database:h2" ;;

        # ===========================================
        # Message Queues & Streaming (10+)
        # ===========================================
        rabbitmq)         echo "pivotal_software:rabbitmq" ;;
        kafka)            echo "apache:kafka" ;;
        activemq)         echo "apache:activemq" ;;
        zeromq|zmq)       echo "zeromq:zeromq" ;;
        nats)             echo "nats:nats_server" ;;
        pulsar)           echo "apache:pulsar" ;;
        mosquitto)        echo "eclipse:mosquitto" ;;
        redis-stream)     echo "redis:redis" ;;
        celery)           echo "celeryproject:celery" ;;
        sidekiq)          echo "sidekiq:sidekiq" ;;

        # ===========================================
        # Container & Orchestration (15+)
        # ===========================================
        docker)           echo "docker:docker" ;;
        podman)           echo "redhat:podman" ;;
        containerd)       echo "containerd:containerd" ;;
        runc)             echo "opencontainers:runc" ;;
        cri-o|crio)       echo "kubernetes:cri-o" ;;
        kubectl)          echo "kubernetes:kubectl" ;;
        kubernetes|k8s)   echo "kubernetes:kubernetes" ;;
        helm)             echo "helm:helm" ;;
        istio)            echo "istio:istio" ;;
        linkerd)          echo "linkerd:linkerd" ;;
        rancher)          echo "rancher:rancher" ;;
        openshift)        echo "redhat:openshift" ;;
        nomad)            echo "hashicorp:nomad" ;;
        mesos)            echo "apache:mesos" ;;
        swarm)            echo "docker:swarm" ;;

        # ===========================================
        # Infrastructure & DevOps (20+)
        # ===========================================
        terraform)        echo "hashicorp:terraform" ;;
        ansible)          echo "redhat:ansible" ;;
        puppet)           echo "puppet:puppet" ;;
        chef)             echo "chef:chef" ;;
        saltstack|salt)   echo "saltstack:salt" ;;
        vagrant)          echo "hashicorp:vagrant" ;;
        packer)           echo "hashicorp:packer" ;;
        vault)            echo "hashicorp:vault" ;;
        jenkins)          echo "jenkins:jenkins" ;;
        gitlab)           echo "gitlab:gitlab" ;;
        gitea)            echo "gitea:gitea" ;;
        gogs)             echo "gogs:gogs" ;;
        drone)            echo "drone:drone" ;;
        circleci)         echo "circleci:circleci" ;;
        argocd|argo-cd)   echo "argoproj:argo-cd" ;;
        flux)             echo "fluxcd:flux" ;;
        prometheus)       echo "prometheus:prometheus" ;;
        grafana)          echo "grafana:grafana" ;;
        datadog)          echo "datadog:agent" ;;
        newrelic)         echo "newrelic:agent" ;;
        jaeger)           echo "jaegertracing:jaeger" ;;
        zipkin)           echo "apache:zipkin" ;;

        # ===========================================
        # Package Managers (10+)
        # ===========================================
        npm)              echo "npmjs:npm" ;;
        yarn)             echo "yarnpkg:yarn" ;;
        pnpm)             echo "pnpm:pnpm" ;;
        pip|pip3)         echo "pypa:pip" ;;
        pipenv)           echo "pypa:pipenv" ;;
        poetry)           echo "python-poetry:poetry" ;;
        gem|rubygems)     echo "rubygems:rubygems" ;;
        bundler)          echo "bundler:bundler" ;;
        cargo)            echo "rust-lang:cargo" ;;
        composer)         echo "getcomposer:composer" ;;
        maven|mvn)        echo "apache:maven" ;;
        gradle)           echo "gradle:gradle" ;;
        nuget)            echo "nuget:nuget" ;;

        # ===========================================
        # Common Utilities & CLI Tools (25+)
        # ===========================================
        curl)             echo "curl:curl" ;;
        wget)             echo "gnu:wget" ;;
        git)              echo "git-scm:git" ;;
        vim|neovim|nvim)  echo "vim:vim" ;;
        emacs)            echo "gnu:emacs" ;;
        tmux)             echo "tmux:tmux" ;;
        screen)           echo "gnu:screen" ;;
        zsh)              echo "zsh:zsh" ;;
        bash)             echo "gnu:bash" ;;
        fish)             echo "fishshell:fish" ;;
        jq)               echo "stedolan:jq" ;;
        yq)               echo "mikefarah:yq" ;;
        fzf)              echo "junegunn:fzf" ;;
        ripgrep|rg)       echo "burntsushi:ripgrep" ;;
        fd)               echo "sharkdp:fd" ;;
        bat)              echo "sharkdp:bat" ;;
        exa|eza)          echo "ogham:exa" ;;
        htop)             echo "htop:htop" ;;
        sudo)             echo "sudo:sudo" ;;
        doas)             echo "openbsd:doas" ;;
        rsync)            echo "samba:rsync" ;;
        tar)              echo "gnu:tar" ;;
        make)             echo "gnu:make" ;;
        cmake)            echo "cmake:cmake" ;;
        ninja)            echo "ninja-build:ninja" ;;

        # ===========================================
        # Browsers & Electron Apps (10+)
        # ===========================================
        chrome|chromium)  echo "google:chrome" ;;
        firefox)          echo "mozilla:firefox" ;;
        safari)           echo "apple:safari" ;;
        edge)             echo "microsoft:edge" ;;
        brave)            echo "brave:brave" ;;
        opera)            echo "opera:opera" ;;
        electron)         echo "electronjs:electron" ;;
        vscode|code)      echo "microsoft:visual_studio_code" ;;
        slack)            echo "slack:slack" ;;
        discord)          echo "discord:discord" ;;

        # ===========================================
        # Compression & Archiving (10+)
        # ===========================================
        gzip)             echo "gnu:gzip" ;;
        bzip2)            echo "bzip:bzip2" ;;
        xz|liblzma)       echo "tukaani:xz" ;;
        zstd)             echo "facebook:zstandard" ;;
        lz4)              echo "lz4:lz4" ;;
        p7zip|7z|7zip)    echo "7-zip:7-zip" ;;
        unrar|rar)        echo "rarlab:unrar" ;;
        zip|unzip)        echo "info-zip:unzip" ;;
        pigz)             echo "pigz:pigz" ;;
        pbzip2)           echo "compression:pbzip2" ;;

        # ===========================================
        # Email & Communication (10+)
        # ===========================================
        postfix)          echo "postfix:postfix" ;;
        sendmail)         echo "sendmail:sendmail" ;;
        exim)             echo "exim:exim" ;;
        dovecot)          echo "dovecot:dovecot" ;;
        cyrus-imapd|cyrus) echo "cmu:cyrus_imap" ;;
        opendkim)         echo "opendkim:opendkim" ;;
        spamassassin)     echo "apache:spamassassin" ;;
        amavisd|amavis)   echo "amavis:amavisd-new" ;;
        mailman)          echo "gnu:mailman" ;;
        roundcube)        echo "roundcube:roundcube" ;;

        # ===========================================
        # Virtualization & Emulation (10+)
        # ===========================================
        qemu)             echo "qemu:qemu" ;;
        virtualbox|vbox)  echo "oracle:virtualbox" ;;
        vmware)           echo "vmware:vmware_workstation" ;;
        libvirt)          echo "redhat:libvirt" ;;
        kvm)              echo "linux:kvm" ;;
        xen)              echo "xen:xen" ;;
        hyper-v)          echo "microsoft:hyper-v" ;;
        parallels)        echo "parallels:parallels_desktop" ;;
        bochs)            echo "bochs:bochs" ;;
        dosbox)           echo "dosbox:dosbox" ;;

        # ===========================================
        # Networking Tools (15+)
        # ===========================================
        bind|named)       echo "isc:bind" ;;
        dnsmasq)          echo "thekelleys:dnsmasq" ;;
        unbound)          echo "nlnetlabs:unbound" ;;
        dhcpd|isc-dhcp)   echo "isc:dhcp" ;;
        openvpn)          echo "openvpn:openvpn" ;;
        wireguard)        echo "wireguard:wireguard" ;;
        strongswan)       echo "strongswan:strongswan" ;;
        ipsec)            echo "strongswan:strongswan" ;;
        iptables)         echo "netfilter:iptables" ;;
        nftables)         echo "netfilter:nftables" ;;
        tcpdump)          echo "tcpdump:tcpdump" ;;
        netcat|nc)        echo "gnu:netcat" ;;
        socat)            echo "dest-unreach:socat" ;;
        iperf|iperf3)     echo "iperf:iperf" ;;
        mtr)              echo "mtr:mtr" ;;

        # ===========================================
        # Operating System Components (10+)
        # ===========================================
        linux|kernel)     echo "linux:linux_kernel" ;;
        glibc|libc)       echo "gnu:glibc" ;;
        systemd)          echo "systemd:systemd" ;;
        dbus)             echo "freedesktop:dbus" ;;
        polkit)           echo "freedesktop:polkit" ;;
        pam)              echo "linux-pam:linux-pam" ;;
        selinux)          echo "selinuxproject:selinux" ;;
        apparmor)         echo "canonical:apparmor" ;;
        grub)             echo "gnu:grub" ;;
        udev)             echo "systemd:systemd" ;;

        # ===========================================
        # Logging & Monitoring (10+)
        # ===========================================
        syslog-ng)        echo "balabit:syslog-ng" ;;
        rsyslog)          echo "rsyslog:rsyslog" ;;
        fluentd)          echo "fluentd:fluentd" ;;
        fluent-bit)       echo "fluentbit:fluent-bit" ;;
        logstash)         echo "elastic:logstash" ;;
        filebeat)         echo "elastic:filebeat" ;;
        telegraf)         echo "influxdata:telegraf" ;;
        collectd)         echo "collectd:collectd" ;;
        nagios)           echo "nagios:nagios" ;;
        zabbix)           echo "zabbix:zabbix" ;;

        # ===========================================
        # File Sharing & Storage (10+)
        # ===========================================
        samba|smb)        echo "samba:samba" ;;
        nfs-utils|nfs)    echo "linux-nfs:nfs-utils" ;;
        vsftpd)           echo "beasts:vsftpd" ;;
        proftpd)          echo "proftpd:proftpd" ;;
        minio)            echo "minio:minio" ;;
        nextcloud)        echo "nextcloud:nextcloud" ;;
        owncloud)         echo "owncloud:owncloud" ;;
        seafile)          echo "seafile:seafile" ;;
        syncthing)        echo "syncthing:syncthing" ;;
        restic)           echo "restic:restic" ;;
        borgbackup|borg)  echo "borgbackup:borg" ;;

        # Unknown package
        *)                echo "" ;;
    esac
}

# Convert package name and version to CPE 2.3 format
# Usage: package_to_cpe "openssl" "3.0.10"
package_to_cpe() {
    local package="$1"
    local version="$2"

    # Look up in CPE map
    local cpe_info
    cpe_info=$(get_cpe_mapping "$package")

    if [ -z "$cpe_info" ]; then
        # Unknown package - use generic format
        local normalized
        normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]' | sed 's/-bin$//; s/-dev$//; s/-libs$//')
        echo "cpe:2.3:a:*:${normalized}:${version}:*:*:*:*:*:*:*"
    else
        local vendor product
        vendor=$(echo "$cpe_info" | cut -d: -f1)
        product=$(echo "$cpe_info" | cut -d: -f2)
        echo "cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*"
    fi
}

# Parse version string to extract major.minor.patch
# Usage: parse_version "3.0.10-1ubuntu1"
parse_version() {
    local version="$1"

    # Extract version numbers (handles formats like 3.0.10, 3.0.10-1, 3.0.10_1)
    echo "$version" | grep -oE '^[0-9]+(\.[0-9]+)*' | head -1
}

# Compare versions (returns 0 if v1 >= v2, 1 otherwise)
# Usage: version_gte "3.0.10" "3.0.5"
version_gte() {
    local v1="$1"
    local v2="$2"

    # Use sort -V for version comparison
    local higher
    higher=$(printf '%s\n%s' "$v1" "$v2" | sort -V | tail -1)

    if [ "$higher" = "$v1" ]; then
        return 0
    else
        return 1
    fi
}

# Parse host inventory file and extract packages with versions
# Usage: parse_inventory_packages "/path/to/host-inventory.txt"
parse_inventory_packages() {
    local inventory_file="$1"

    if [ ! -f "$inventory_file" ]; then
        echo "Error: Inventory file not found: $inventory_file" >&2
        return 1
    fi

    # Parse Homebrew packages section
    local in_homebrew=0
    local in_applications=0
    local in_security=0
    local in_languages=0

    while IFS= read -r line; do
        # Detect section headers
        if echo "$line" | grep -q "Homebrew Packages:"; then
            in_homebrew=1
            in_applications=0
            in_security=0
            in_languages=0
            continue
        elif echo "$line" | grep -q "Applications.*:"; then
            in_homebrew=0
            in_applications=1
            in_security=0
            in_languages=0
            continue
        elif echo "$line" | grep -q "Security Tools:"; then
            in_homebrew=0
            in_applications=0
            in_security=1
            in_languages=0
            continue
        elif echo "$line" | grep -q "Programming Languages:"; then
            in_homebrew=0
            in_applications=0
            in_security=0
            in_languages=1
            continue
        elif echo "$line" | grep -qE "^[A-Z].*:$"; then
            # New section - reset all flags
            in_homebrew=0
            in_applications=0
            in_security=0
            in_languages=0
            continue
        fi

        # Parse package lines based on section
        if [ "$in_homebrew" -eq 1 ]; then
            # Format: "    package version" or "    package version1 version2"
            local pkg_line
            pkg_line=$(echo "$line" | sed 's/^[[:space:]]*//')
            if [ -n "$pkg_line" ] && [ "$pkg_line" != "..." ]; then
                local pkg_name pkg_version
                pkg_name=$(echo "$pkg_line" | awk '{print $1}')
                pkg_version=$(echo "$pkg_line" | awk '{print $2}')
                if [ -n "$pkg_name" ] && [ -n "$pkg_version" ] && [ "$pkg_version" != "not" ]; then
                    echo "${pkg_name}:${pkg_version}"
                fi
            fi
        elif [ "$in_security" -eq 1 ] || [ "$in_languages" -eq 1 ]; then
            # Format: "  Tool: version"
            if echo "$line" | grep -q ":"; then
                local tool_name tool_version
                tool_name=$(echo "$line" | sed 's/^[[:space:]]*//' | cut -d: -f1 | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
                tool_version=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//' | awk '{print $1}')
                if [ -n "$tool_name" ] && [ -n "$tool_version" ] && [ "$tool_version" != "not" ]; then
                    # Clean up version string
                    tool_version=$(parse_version "$tool_version")
                    if [ -n "$tool_version" ]; then
                        echo "${tool_name}:${tool_version}"
                    fi
                fi
            fi
        fi
    done < "$inventory_file"
}

# Get high-priority packages for CVE scanning
# Returns commonly exploited software that should be checked
get_priority_packages() {
    echo "openssl"
    echo "openssh"
    echo "curl"
    echo "git"
    echo "nginx"
    echo "apache"
    echo "postgresql"
    echo "mysql"
    echo "python"
    echo "node"
    echo "php"
    echo "ruby"
    echo "docker"
}

# Check if package is in priority list
is_priority_package() {
    local package="$1"
    local normalized
    normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]')

    get_priority_packages | grep -qx "$normalized"
}

# Filter packages to only those with known CPE mappings
filter_known_packages() {
    while IFS=: read -r package version; do
        local cpe_info
        cpe_info=$(get_cpe_mapping "$package")

        if [ -n "$cpe_info" ]; then
            echo "${package}:${version}"
        fi
    done
}

# Get CPE vendor for a package
get_cpe_vendor() {
    local package="$1"
    local cpe_info
    cpe_info=$(get_cpe_mapping "$package")

    if [ -n "$cpe_info" ]; then
        echo "$cpe_info" | cut -d: -f1
    else
        echo "*"
    fi
}

# Get CPE product for a package
get_cpe_product() {
    local package="$1"
    local cpe_info
    cpe_info=$(get_cpe_mapping "$package")

    if [ -n "$cpe_info" ]; then
        echo "$cpe_info" | cut -d: -f2
    else
        local normalized
        normalized=$(echo "$package" | tr '[:upper:]' '[:lower:]' | sed 's/-bin$//; s/-dev$//; s/-libs$//')
        echo "$normalized"
    fi
}
