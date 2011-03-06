#!/usr/bin/env python

import sys

from distutils.core import setup

# this affects the names of all the directories we do stuff with
sys.path.insert(0, './')
from rulegen.version import VERSION


setup(name          = 'rulegen',
      version       = VERSION,
      description   = 'A rule-generator for netfilter and pf.',
      author        = 'Constanze Hausner',
      author_email  = 'constanze@gentoo.org',
      url           = 'http://github.com/constanze/rulegen',
      packages      = ['rulegen'],
      scripts       = ['bin/rulegen'],
      license       = 'GPL',
      )
