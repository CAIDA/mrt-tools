all: 
	$(MAKE) -C src
#	$(MAKE) -C doc

clean: 
	$(MAKE) -C src clean
	$(MAKE) -C test clean

.PHONY: debian test

debian:
	dpkg-buildpackage -b --no-sign

# Note: builddeps must be run as root since it installs the dependencies
# needed to build the package
debian-builddeps:
	sudo apt update
	sudo DEBIAN_FRONTEND=noninteractive apt -y install devscripts equivs
	sudo DEBIAN_FRONTEND=noninteractive mk-build-deps --install \
	  debian/control --remove \
	  --tool='apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes'
	sudo rm -f *.buildinfo *.changes

clean-debian:
	dpkg-buildpackage -rfakeroot -Tclean

# lint on debian package
lintian:
	lintian --no-tag-display-limit --suppress-tags dir-or-file-in-opt \
	  --suppress-tags repeated-path-segment --verbose --info --pedantic

test: all
	$(MAKE) -C test
