# SHS

A command line interface that calculates the security health of an application, system, or code base and returns a single score.

## Installation

### Download

Get the latest pre-built binary for your system's architecture on our [Releases](https://github.com/devops-kung-fu/shs/releases) page.

### Make Executable

```shell
$ chmod +x shs-x.x.x-linux-amd64
```

### Rename and Move to /usr/local/bin/

```shell
$ mv shs-x.x.x-linux-amd64 /usr/local/bin/shs
```

## Usage

- [calculate](#calculate)
- [help](#help)
- [version](#version)

### calculate

`shs calculate [flags]`

- [calculate help](#calculate-help)
- [vector](#vector)

#### calculate help

Outputs help for calculate.

`shs calculate --help`

`shs calculate -h`

```shell
$ shs calculate -h  
Calculates the Security Health Score

Usage:
  shs calculate [flags]

Flags:
  -h, --help                 help for calculate
  -v, --vector stringArray   Calculates security health score based on a single vector string.
```

#### vector

Calculates security health score based on a single vector string.

`shs calculate --vector`

`shs calculate -v`

```shell
$ shs calculate -v CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N
Security Health Score: 582
$ shs calculate -v "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"
Security Health Score: 582
$ shs calculate -v 'CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N'
Security Health Score: 582
```

### help

Outputs usage information.

`shs help`

`shs --help`

`shs -h`

```shell
$ shs -h
Security Security Health Score Calculator

Usage:
  shs [command]

Available Commands:
  calculate   Calculates the Security Health Score
  help        Help about any command

Flags:
  -h, --help      help for shs
  -v, --version   version for shs

Use "shs [command] --help" for more information about a command.
```

### version

Outputs version.

`shs --version`

`shs -v`

```shell
$ shs -v
shs version x.x.x
```