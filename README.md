# dync 0.0.0  
## Overview  
A simple DynDNS client.  
## Supported protocols  
None  
## Configuration  
### `instance:` [List]  
This key contains the configuration for all DynDNS instances as a list. Each instance is represented as a single list item and uses the following keys: `uid`, `ip`, `server`, `mode`.  
#### `uid:` [String]  
The uid should specify a unique name for this instance. It may consist out of the following characters: [A-Z], [a-z], [0-9], [-_+].  
#### `ip:` [Dictionary]  
This section defines the IP source. It must contain the following keys: `origin`, `pattern`, `group`.  
A side note regarding matches: A single pattern may match multiple IP addresses.  
##### `origin:` [String]  
The origin field defines the source from which the IP address is fetched. This address is used for two things: On the one hand, it's used as a reference to determine whether the current address has changed or not. On the other hand, this IP is used as an update-address which will be sent to the server.  
There are three types of origins:  
* `iface://[name]`: specifies an interface as IP source; substitute [name] with the interface's name  
* `http(s)://[address]`: defines a web address / API as IP source; substitute [address] with the API's address  
* `sock://[ip]`: declares a socket using UDP as IP source; substitute [ip] with the server's address  
##### `pattern:` [String]  
The pattern key sets the regular expression to find the IP address. All IP addresses are compared with the pattern independently from each other. This field uses [Python 3 regex syntax](https://docs.python.org/3/library/re.html).  
A side note regarding IPv6 addresses: IPv6 addresses are always expanded before they are compared with the pattern. For example the IPv6 address `fd00:25a:c::25:7c:e` turns into `fd00:025a:000c:0000:0000:0025:007c:000e`.  
##### `group:` [Integer]  
Specifies the group number in the regex pattern to use for the IP address.  
If the value is set to `-1`, the entire match is used as the IP address.  
If the value is set to `-2`, the entire string is used as the IP address.  
#### `server:` [Dictionary]  
This section defines the communication for the update process. The following keys must be present as subkeys: `protocol`, `address`, `domain`, `user`, `password`, `retries`.  
##### `protocol:` [String]  
The protocol field determines the used protocol. See 'Supported protocols' for more details. If a server uses a supported protocol with a customization, please open an issue on [GitHub](https://github.com/FireSpike0/dync).  
##### `address:` [String]  
The address defines the used server address to send the update request to.  
##### `domain:` [String], [List]  
This represents the domain to update during a request.  
If this field is a string, then this string will be passed to the server. You can directly use the server's list format if you're familiar with it.  
If this field is a list, then all values will be joined according to the used protocol, provided the protocol supports multiple hosts. See 'Supported protocols' for more details.  
##### `user:`, `password:` [String]  
These keys define the credentials used for the request.  
##### `retry:` [Integer]  
This key sets the amount of retries after a server error occurred.  
If the value is set to `-1`, infinite retries will be executed.  
#### `mode:` [Integer]  
This key currently can only be an integer and defines the wait time in seconds until the local IP address will be checked again for an update.  
## Changelog  
