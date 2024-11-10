<p>This simple software is designed for a very basic low-level subnet monitoring and is mainly intended to run on a server in continuous mode.<br>
The idea is to collect all MAC addresses in subnets connected to the server and as well as associated hostnames in different protocols such as: DNS, mDNS, UPnP, DHCP, NBNS, LLDP. 
Note that not all hosts have public names and do not always report their names, even if they are present.<br>
You can use server console or a web browser to view the collected data. Simple SMTP notification service can be configured.</p>
<p><strong>This free software comes with ABSOLUTELY NO WARRANTY</strong></p>
<p>
    Building instructions:
    <ol>
        <li>Update and upgrade packages (strongly recommended):<br> sudo apt update<br>sudo apt upgrade</li>
        <li>Install SQLite package, development libraries and header files:<br>sudo apt install sqlite3 libsqlite3-dev</li>
        <li>Install OpenSSL package, development libraries and header files:<br>sudo apt install openssl libssl-dev</li>
        <li>From ‘snmonitor’ main folder execute:<br>make all</li>
    </ol>
</p>
<p>
    Usage:
    <ol>
        <li>Fill in ‘snmonitor.ini’ file</li>
        <li>You can upload MAC vendor database. To get more information run:<br>snmonitor -h</li>
        <li>Run ‘snmonitor’ (<em>Note: using ‘tmux’ may be convenient</em>)</li>
        <li>Press: h + &lt;Enter&gt; to help</li>
        <li>Press: q + &lt;Enter&gt; to quit</li>
    </ol>
</p>
<em>Note: I'm running this software on a Raspberry Pi 4 Model B, Ubuntu Server 22.04 LTS (64-bit)</em>
