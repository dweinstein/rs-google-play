rs-gpapi
==========

Rust conversion (in-progress) from https://github.com/dweinstein/node-google-play.

Documentation can be found [here](https://dweinstein.github.io/rs-google-play/gpapi/), but no promise it's the latest.

# Usage

```
gpapi-cli 1.0
David Weinstein <dweinst AT insitusec DOT com>
Interact with play store APIs

USAGE:
    gpapi-cli [FLAGS] [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Sets the level of verbosity

OPTIONS:
    -c, --config <FILE>    Sets a custom config file

SUBCOMMANDS:
    bulk-details        Get details for a list of packages via `bulkDetails` API.
    details             Get details for a package.
    get-download-url    Get download url (purchase if necessary) for a package
    help                Prints this message or the help of the given subcommand(s)
```

## bulk-details

```
gpapi-cli-bulk-details 1.0
Get details for a list of packages via `bulkDetails` API.

USAGE:
    gpapi-cli bulk-details [FLAGS] <PKGS>...

FLAGS:
    -d               print debug information
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <PKGS>...    Supply (multiple) package names (up to 100-150).
```


## details

```
gpapi-cli-details 1.0
Get details for a package.

USAGE:
    gpapi-cli details [FLAGS] <PKG>

FLAGS:
    -d               print debug information
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <PKG>    Sets the package name to use
```


## get-download-url

```
gpapi-cli-get-download-url 1.0
Get download url (purchase if necessary) for a package

USAGE:
    gpapi-cli get-download-url [FLAGS] <PKG> <VC>

FLAGS:
    -d               print debug information
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <PKG>    Sets the package name to use
    <VC>     Application version code
```

TODO
----
- [x] login and get auth token
- [ ] support all api requests
  - [x] details request
  - [x] bulkDetails
  - [ ] apk download
- [ ] set code license

