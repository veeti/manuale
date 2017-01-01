# 1.1.0 (January 1, 2017)

* Added support for HTTP authorization. (contributed by GitHub user @mbr)

* Added support for registration with an existing key. (contributed by GitHub user @haddoncd)

* Using an existing CSR no longer requires the private key. (contributed by GitHub user @eroen)

# 1.0.3 (August 27, 2016)

* Fixed handling of recycled authorizations: if a domain is already authorized, the server no longer allows reauthorizing it until expired.

* Existing EC keys can now be used to issue certificates. (Support for generating EC keys is not yet implemented.)

# 1.0.2 (March 20, 2016)

* The authorization command now outputs proper DNS record lines.

# 1.0.1 (February 9, 2016)

* Private key files are now created with read permission for the owner only (`0600` mode).

* The README is now converted into reStructuredText for display in PyPI.

* Classified as Python 3 only in PyPI.

# 1.0.0 (February 6, 2016)

Initial release.
