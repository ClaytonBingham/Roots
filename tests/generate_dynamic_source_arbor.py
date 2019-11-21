from roots.core import Roots,Roots_math
from roots.kmd import KMDD
from roots.graphmethods import GraphMethods
from roots.swcToolkit import swcToolkit
from roots.root2neuron import Root2Hoc,Root2Py
from roots.microstructures import Microstructures
import os
from roots.visualization import swcVisualizer
import numpy as np
import random
import os

#create dictionary to scale diameters of sections corresponding to microstructures
label_scalars={}

#scale
label_scalars['node'] = 1
label_scalars['internode'] = 1/0.65
label_scalars['paranode1'] = 1/0.65
label_scalars['paranode2'] = 1/0.65
label_scalars['interbouton'] = 1
label_scalars['bouton'] = 7

def return_random_params():
	#instantiate Roots core parameters
	a = random.choice(np.arange(1,3.0,0.25))
	b = random.choice(np.arange(300,475,25))
	c = random.choice(np.arange(1.5,3.0,0.25))
	d = random.choice(np.arange(300,425,25))
	return(a,b,c,d)

def make_axon(outputdir):
	#use Roots to grow axon
	a,b,c,d = return_random_params()
	source_point,targets = np.random.rand(300,3)*100.0
	root = Roots(source_point, targets, np.pi/a, b, np.pi/c, d, 100, KMDDproperties=dict(zip(['cluster_reduce','tri_edge_length_max','source','open_points'],[0.25,300,source_inner,new_points[:source_index]+new_points[source_index+1:]])))
	graph_nodes = root.grow()
	swcname = outputdir+axe_type+'_'+str(a)+'_'+str(b)+'_'+str(c)+'_'+str(d)+'.swc'
	root.to_swc(swcname) #save axon to swc
	return(root)

def add_myelin_boutons(arbor,bouton_branch_list,myelin_branch_list,diam_scalars):
	#add myelin and boutons to existing arbor (by interbifurcated region)
	mstruct = Microstructures()
	arbor,labels = mstruct.add_microstructures_to_arbor(morph,[key for key in morph.keys() if key in mlist],[key for key in morph.keys() if key not in mlist])
	arbor = mstruct.apply_microstructures_diameter_scalars(arbor,labels,diam_scalars,replace=False)
	return(arbor,labels)

def mplot_arbor(arbor):
	#plot sectioned arbor in mayavi
	visualizer = swcVisualizer()
	visualizer.mplot_sectioned_arbor(arbor)

def shift_rotate_arbor(arbor2,shiftxyz,elevation,azimuth):
	#shift and rotate sectioned arbor in space
	arbor2 = swctool.move_morphology(arbor2,[762.2999880000001, 2337.4, -63.971000000000004])
	arbor2 = swctool.rotate_morphology(arbor2,[0,0,0],elevation=90.0)
	return(arbor2)

if __name__ == "__main__":
	root = make_axon(os.getcwd()+'/')
	root,labels = add_myelin_boutons(arbor,list(arbor.keys()),[],label_scalars)
	root = shift_rotate_arbor(arbor,[0,0,0],0,0)
	mplot_arbor(arbor)
	nrn_writer = Root2Py()
	nrn_writer.arbor_to_hoc(arbor,labels)
