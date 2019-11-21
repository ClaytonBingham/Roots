ROOTS: Ruled-Optimum Ordered Tree System

ROOTS is a package designed to take experimentally determined morphometric data and return an artificial neuronal arbor which satisfies the user-defined parameters.

Originally this package was written to aid the construction of biologically realistic neural models for use in computational studies of extracellular electrical stimulation but it can be used for diverse neural modeling problems.

Installation
Download the package and while in root directory call: 
```
python setup.py install
```

Usage

```
#import roots modules
from roots.core import Roots,Roots_math
from roots.kmd import KMDD
from roots.graphmethods import GraphMethods

#import a few helper libraries
import numpy as np
import random
import os

#generate some random parameters for roots to use
def return_random_params():
	a = random.choice(np.arange(1,3.0,0.25))
	b = random.choice(np.arange(300,475,25))
	c = random.choice(np.arange(1.5,3.0,0.25))
	d = random.choice(np.arange(300,425,25))
	return(a,b,c,d)

#create source point, target points, and pass them to Roots.
#call .grow() method and specify output .swc file to write results to
def make_axon(outputdir):
	a,b,c,d = return_random_params()
	source_point,targets = np.random.rand(300,3)*100.0
	root = Roots(source_point, targets, np.pi/a, b, np.pi/c, d, 100, KMDDproperties=dict(zip(['cluster_reduce','tri_edge_length_max','source','open_points'],[0.25,300,source_inner,new_points[:source_index]+new_points[source_index+1:]])))
	graph_nodes = root.grow()
	swcname = outputdir+axe_type+'_'+str(a)+'_'+str(b)+'_'+str(c)+'_'+str(d)+'.swc'
	root.to_swc(swcname) #save axon to swc
	return(root)

```

Roots() arguments include the following:

source - point from which the tree begins (not a member of open 'points' which is a separate argument)
points - open points through which the tree must grow (does not include 'source')
s_ang - branch extension angle threshold
s_dist - branch extension distance threshold
b_ang - bifurcation angle threshold
b_dist - bifurcation distance threshold
rel_source_dist - (disabled for KMDD mode growing) minimum distance down the active branch on which to find a bifurcation point
KMDDproperties - properties of k-means, delaunay triangulation for 'likely path' sorting for dynamic source updating fibers provided as a dictionary
	KMDDproperties:
			cluster_reduce - proportion of reduction for k-means clustering (i.e. if cluster_reduce == 0.25 then the number of clusters will equal 25% of the number of open points)
			tri_edge_length_max - the meshing distance threshold below which delaunay triangulated edges will be returned (i.e. triangulated edges longer than tri_edge_length_max will be removed from the triangulation)
			openpoints - open points to be clustered and meshed (same as ROOTS argument 'points')
			source - source point from which a tree will be grown (same as ROOTS argument 'source')

```
#finally run the make_axon function with the output directory as the input.
if __name__ == "__main__":
	root = make_axon(os.getcwd()+'/')
```

