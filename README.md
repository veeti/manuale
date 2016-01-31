# ManuaLE

manuale is a lightweight [Let's Encrypt](https://letsencrypt.org)/[ACME](https://github.com/ietf-wg-acme/acme/) client designed for a manual workflow. It contains no automation features whatsoever and is intended to be called by a human.

## Why?

Isn't the point of Let's Encrypt to be automatic and seamless? Maybe, but here's some reasons:

* You're not comfortable with an automatic process handling something as critical, or your complex infrastructure doesn't allow it in the first place.

* You already have perfect configuration management with something like Ansible. Renewing is a matter of dropping in a new certificate. With a manual client that works, it's literally a minute of work.

* You want the traditional and authentic SSL installation experience of copying files you don't understand to your server, searching for configuration instructions and praying that it works.

## Features

* Simple interface with no hoops to jump through. Keys and certificate signing requests are automatically generated: no more cryptic OpenSSL one-liners.

* Support for DNS validation. No need to figure out how to serve challenge files from a live domain. (In fact, that's the only validation method supported.)

* Authorization is separate from certificate issuance. Authorizations last for months on Let's Encrypt: there's no need to waste time validating the domain every time you renew the certificate.

* Obviously, runs without root access. Use it from any machine you want, it doesn't care. Internet connection recommended.

* Awful, undiscoverable name.

* And finally, if the `openssl` binary is your spirit animal, you can still bring your own keys and/or CSR's. Everybody wins.

## Installation

For now, install through the repository:

    git clone https://github.com/veeti/manuale ~/.manuale
    cd ~/.manuale
    virtualenv3 env
    env/bin/python setup.py install
    ln -s env/bin/manuale ~/.bin/

You need Python 3. It's 2016.

(Assuming that you have a `~/.bin` directory that's in your `PATH`.)

## Usage

You need to create an account once. To do so, call `manuale register [email]`. This will create a new account key for you. Follow the registration instructions.

Once that's done, you'll have your account saved in `account.json` in the current directory. You'll need this to do anything useful. Oh, and it contains your private key, so keep it safe and secure.

`manuale` expects the account file to be in your working directory by default, so you'll probably want to make a specific directory to do all your certificate stuff in. Likewise, created certificates get saved in the current path by default.

Next up, verify your the domains you want a certificate for one-by-one with `manuale authorize [domain]`. This will show you the DNS record you need to create and wait for you to do it. For example, you might do it for `example.com` and `www.example.com`.

Once that's done, you can finally get down to business. Run `manuale issue example.com www.example.com` to get your certificate. It'll save the key, certificate and certificate with intermediate to the working directory.

There's plenty of documentation inside each command. Run `manuale [command] -h` for details.

## See also

* [Best practices](https://wiki.mozilla.org/Security/Server_Side_TLS)
* [Configuration generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/)
* [Test your config](https://www.ssllabs.com/ssltest/)

## License

**The MIT License (MIT)**

Copyright © 2016 Veeti Paananen

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
