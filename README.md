# valgrind Website

This is the source code for our website, built with [staticjinja](https://staticjinja.readthedocs.io/en/latest/) and a couple of custom build scripts.

## Development

This repo is configured for the [just](https://just.systems/) command runner. To install dependencies and build the site to `/build`, run:

```sh
just install build
```

To start a development server, run:

```sh
just serve
```