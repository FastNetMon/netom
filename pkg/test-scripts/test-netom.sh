#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nNETOM VERSION:"
    VER=$(netom --version)
    echo $VER

    echo -e "\nNETOM CONF DIR:"
    ls -lR /etc/netom/

    echo -e "\nNETOM CONF:"
    cat /etc/netom/netom.conf

    echo -e "\nNETOM SERVICE STATUS BEFORE ENABLE:"
    systemctl status netom || true

    echo -e "\nNETOM MAN PAGE (first 20 lines only):"
    man -P cat netom | head -n 20 || true

    ;;

  post-upgrade)
    echo -e "\nNETOM VERSION:"
    netom --version

    echo -e "\nNETOM CONF DIR:"
    ls -lR /etc/netom/
    
    echo -e "\nNETOM CONF:"
    cat /etc/netom/netom.conf
    
    echo -e "\nNETOM SERVICE STATUS:"
    systemctl status netom || true
    
    echo -e "\nNETOM MAN PAGE (first 20 lines only):"
    man -P cat netom | head -n 20 || true

    ;;
esac
