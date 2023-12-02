# GoodSniffer

Welcome to the GoodSniffer, a highly customizable and flawless tool for network analysis.

## Overview

My Python based Packet Sniffer is a superior tool in the realm of network analysis. It's built with a focus on customization and reliability, ensuring that it works flawlessly in various scenarios.

## Features

- **Highly Customizable**: The Python Packet Sniffer is designed to be flexible. You can easily adjust its settings to suit your specific needs, making it a versatile tool for any network analysis task.
- **Flawless Operation**: I've put a lot of effort into ensuring that this tool works perfectly under different conditions. It's been thoroughly tested and proven to perform without any issues.
- **Detailed Packet Information**: The sniffer provides detailed information about each packet, including the serial number, timestamp, protocol, packet length, destination MAC, source MAC, destination host, and source host. AND IF YOU ARE A POWERUSER or a human interested in reading through raw ethernet frames, guess what, the GoodSniffer's gotcha.

## How to Use

- `goodsniffer.py`: This is the main script that runs the packet sniffer. It binds to a specific network interface (whose IP you can provide in the variable interface IP) and listens for incoming packets, printing detailed information about each one.

-To find the IP for your interface, just use `ipconfig` on windows, `ifconfig` on unix like operating systems and take note of the IPV4 address of the network interface of your choice that you'd like to listen on.

-Although you can also use the file `ethdata.py` to get a nice look at what's floating between the fiber cables that help you reach your favorite server.

-`imtoolazytoformatallprotocols.py` is a script that fethches all the current IANA protocol numbers and their names and formats them in a format that you can simply copy and paste into the protocol_map dictionary to update it, making the good sniffer a timeless masterpiece.

1. Clone the repository: `git clone https://github.com/thedabworthyglitch/packet-sniffer.git`
2. Navigate to the project directory: `cd packet-sniffer`
3. Run the script: `python3 sniffer.py`

## Contributing

I welcome contributions!

## License

This project is licensed under the terms of the MIT license. See [LICENSE](LICENSE) for more details.

## Contact

If you have any questions or feedback, please feel free to contact me.

Happy sniffing!
