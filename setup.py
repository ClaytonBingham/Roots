from distutils.core import setup

DESCRIPTION = "Grows artificial axon arbors based on morphometrics extracted from full axon reconstructions."
LONG_DESCRIPTION = "ROOTS: Ruled-Optimum Ordered Tree System. ROOTS is a package designed to take experimentally determined morphometric data and return an artificial neuronal arbor which satisfies the user-defined parameters. Originally this package was written to aid the construction of biologically realistic neural models for use in computational studies of extracellular electrical stimulation but it can be used for diverse neural modeling problems.
NAME = "Roots"
AUTHOR = "Clayton Bingham"
AUTHOR_EMAIL = "clayton.bingham@gmail.com"
MAINTAINER = "Clayton Bingham"
MAINTAINER_EMAIL = "clayton.bingham@gmail.com"
LICENSE = 'BSD'
REQUIREMENTS = [
		numpy',
		matplotlib',
		networkx',
		mayavi',
		mpl_toolkits',
		scipy',
		scikit-learn'
		]
VERSION = '0.1'

setup(name=NAME,
      version=VERSION,
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      author=AUTHOR,
      author_email=AUTHOR_EMAIL,
      maintainer=MAINTAINER,
      maintainer_email=MAINTAINER_EMAIL,
      download_url=DOWNLOAD_URL,
      license=LICENSE,
      packages=['roots'],
      install_requires=REQUIREMENTS,
      package_data={}
     )
