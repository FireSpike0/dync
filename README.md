# dync 1.0.0  
## Overview  
A simple DynDNS client.  
## Compatibility  
dync is fully compatible with Linux and other Unix-like systems. Except for the daemon mode, it's also compatible with Windows.  
Both versions of PyYaml's `load` function are supported. This means that dync is compatible with the new one with the `Loader` parameter as well as with the old one without it.  
## Supported protocols  
| Protocol name | Specification URL                       | Internal name | Maximal hosts |  
| ------------- | --------------------------------------- | ------------- | -------------:|  
| DynDNS2       | https://help.dyn.com/remote-access-api/ | dyndns2       | 20            |  
## Command-line arguments  
Common layout: `dync [global parameters] [module] [module-specific parameters]`  
### Global parameters  
| Name | Shorthand | Longhand      | Type         | Value                                             | Default          | Mandatory | Description                             | Example                    |  
| ---- | --------- | ------------- | ------------ | ------------------------------------------------- | ---------------- | --------- | --------------------------------------- | -------------------------- |  
|      | `-v`      | `--verbosity` | Single-value | {`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`} | `INFO`           | No        | Sets the verbosity level of the logger. | `--verbosity INFO`         |  
|      | `-c`      | `--config`    | Single-value | Absolute filepath                                 | `/etc/dync.yaml` | No        | Changes the used configuration file.    | `--config /root/dync.yaml` |  
### Modules  
#### `app`  
The `app` module is responsible for the execution of dync as app.  
Currently, it can be only used to start dync as app. The `command` parameter is mandatory to ensure compatibility with further versions.  
| Name      | Shorthand | Longhand | Type         | Value   | Default          | Mandatory | Description                                          | Example         |  
| --------- | --------- | -------- | ------------ | ------- | ---------------- | --------- | ---------------------------------------------------- | --------------- |  
| `command` |           |          | Single-value | `start` |                  | Yes       | Defines the action / command to be executed by dync. | `... app start` |  
#### `daemon`  
The `daemon` module handles the execution as daemon.  
Please note, that dync only allows one daemonized process simultaneously.  
| Name      | Shorthand | Longhand | Type         | Value                        | Default          | Mandatory | Description                                          | Example              |  
| --------- | --------- | -------- | ------------ | ---------------------------- | ---------------- | --------- | ---------------------------------------------------- | -------------------- |  
| `command` |           |          | Single-value | {`start`, `stop`, `restart`} |                  | Yes       | Defines the action / command to be executed by dync. | `... daemon restart` |  
#### `version`  
The `version` module shows the version information.  
This module has no parameters at all.  
| Name | Shorthand | Longhand | Type | Value | Default | Mandatory | Description | Example |  
| ---- | --------- | -------- | ---- | ----- | ------- | --------- | ----------- | ------- |  
#### `help`  
The `help` module prints the help of a specified module.  
| Name     | Shorthand | Longhand | Type         | Value                                        | Default | Mandatory | Description                | Example           |  
| -------- | --------- | -------- | ------------ | -------------------------------------------- | ------- | --------- | -------------------------- | ----------------- |  
| `target` |           |          | Single-value | {`main`, `app`, `daemon`, `version`, `help`} | `help`  | No        | Selects a specific module. | `... help daemon` |  
A note regarding the `target` parameter: The value `main` refers to the global options.  
## Configuration  
dync uses PyYaml (see `dependencies.yml`) to parse the configuration file. All yaml specific syntax rules supported by PyYaml can be used here, provided the values are still evaluable for the program.  
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
## Logging  
dync stores it's log file under `/var/log/dync`. The used format was kept relatively simple, and an entry looks like this:  
`[2020-10-05 11:05:19 / INFO] @ 120419(Server) : A sample log message was sent.`  
* `2020-10-05 11:05:19`: time of occurrence  
* `INFO`: verbosity level  
* `120419`: PID of the logging process  
* `Server`: thread name (equals to instance name)  
* `A sample log message was sent.`: log message  
## Notes  
### SocketProvider implementation  
A short sample implementation to provide the current IP address over a socket can be found under `./sample/socket_provider.py`.  
**Important:** Make sure to bind the server-side socket to the client-side configured address, especially when using IPv6 connectivity. Otherwise, the client may ignore the received addresses, because they were seemingly sent from another machine even if that's not the case.  
## Credits  
Sander Marechal - [A simple unix/linux daemon in Python](https://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/)  
## Changelog  
### Version 1.0.0  
* Common  
  * Added execution mode `app`  
  * Added execution mode `daemon`  
  * Added command-line interface  
  * Added YAML configuration file  
  * Added daemon PID file  
  * Added logging mechanism  
  * Added file logger  
  * Added OS specific path selection  
* Functionality  
  * Added basic update mechanism  
  * Added interface address provider  
  * Added socket address provider  
  * Added web address provider  
  * Added DynDNS2 address updater  
