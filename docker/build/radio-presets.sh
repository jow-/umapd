#!/bin/sh

sleep 1

echo "" > /etc/config/wireless

/sbin/wifi config

radio_num=0

while uci -q set "wireless.@wifi-device[$radio_num].country=US"; do
    case "$((radio_num % 3))" in
        0) band="5g"; freq_pattern="49[1-8].|5[1-8].." ;;
        1) band="2g"; freq_pattern="24.." ;;
        2) band="6g"; freq_pattern="59..|6...|7[01].." ;;
    esac

    phy=$(iwinfo nl80211 phyname "@wifi-device[$radio_num]")

    first_channel=$(
        iw phy "$phy" info | \
            grep -vE '\b(disabled|no IR)\b' | \
            sed -rne "s#^\t+\* ($freq_pattern)\.?[0-9]* MHz \[([0-9]+)\] .+\$#\2#p" | \
            head -n1
    )

    if [ -n "$first_channel" ]; then
        uci set "wireless.@wifi-device[$radio_num].band=$band"
        uci set "wireless.@wifi-device[$radio_num].channel=$first_channel"
    fi

    uci set "wireless.@wifi-device[$radio_num].ldpc=0"
    uci set "wireless.@wifi-device[$radio_num].rx_stbc=0"
    uci set "wireless.@wifi-device[$radio_num].max_amsdu=0"
    uci set "wireless.@wifi-device[$radio_num].disabled=0"

    case " $(uci get umapd.@agent[0].radio) " in
        *" $phy "*) : ;;
        *) uci add_list "umapd.@agent[0].radio=$phy" ;;
    esac

    radio_num=$((radio_num + 1))
done

while uci -q delete "wireless.@wifi-iface[0]"; do
    :
done

uci commit wireless
uci commit umapd
