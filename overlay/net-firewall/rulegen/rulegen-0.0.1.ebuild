# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="3"
PYTHON_DEPEND="2:2.6"
SUPPORT_PYTHON_ABIS="1"
RESTRICT_PYTHON_ABIS="2.[45] 3.*"

inherit distutils

DESCRIPTION="A rule-generator for netfilter and pf."
HOMEPAGE="http://github.com/constanze/rulegen"
SRC_URI="http://dev.gentoo.org/~constanze/${P}.tar.gz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

DEPEND="dev-python/dpkt
		dev-python/ipaddr
		"
RDEPEND="${DEPEND}"

DOCS="README"

src_compile() {
	:
}

src_install() {
	distutils_src_install
	dodir /etc/rulegen
	cp etc/rulegen.cfg "${D}"/etc/rulegen
}
