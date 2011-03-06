# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="3"
PYTHON_DEPEND="2:2.6"
RESTRICT_PYTHON_ABIS="2.[45] 3.*"
SUPPORT_PYTHON_ABIS="1"

inherit distutils

DESCRIPTION="An IPv4/IPv6 manipulation library in Python."
HOMEPAGE="http://code.google.com/p/ipaddr-py/"
SRC_URI="http://${PN}-py.googlecode.com/files/${P}.tar.gz"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

DEPEND=""
RDEPEND=""

DOCS="PKG-INFO README RELEASENOTES"

src_test() {
	testing() {
		PYTHONPATH="build-${PYTHON_ABI}/lib" "$(PYTHON)" ipaddr_test.py
	}
	python_execute_function testing
}

src_install() {
	distutils_src_install
}
