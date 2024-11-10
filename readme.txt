This simple software is designed for a very basic low-level subnet monitoring and is mainly intended to run on a server in continuous mode.
The idea is to collect all MAC addresses in subnets connected to the server and as well as associated hostnames in different protocols such as: DNS, mDNS, UPnP, DHCP, NBNS, LLDP. Note that not all hosts have public names and do not always report their names, even if they are present.
You can use server console or a web browser to view the collected data. Simple SMTP notification service can be configured.

This free software comes with ABSOLUTELY NO WARRANTY.

Building instructions:

1. Update and upgrade packages (strongly recommended):
    sudo apt update
    sudo apt upgrade

2. Install SQLite package, development libraries and header files:
    sudo apt install sqlite3 libsqlite3-dev

3. Install OpenSSL package, development libraries and header files:
    sudo apt install openssl libssl-dev

4. From ‘snmonitor’ main folder execute:
    make all

Usage:

1. Fill in ‘snmonitor.ini’ file

2. You can upload MAC vendor database. To get more information run:
    snmonitor -h

3. Run ‘snmonitor’ (Note:  using ‘tmux’ may be convenient)

4. Press h + <Enter> to help

5. Press q + <Enter> to quit

Note: I’m running this software on a Raspberry Pi 4 Model B, Ubuntu Server 22.04 LTS (64-bit)
