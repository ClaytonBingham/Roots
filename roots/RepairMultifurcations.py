import pandas as pd
from roots.swcToolkit import swcToolkit
import swc2vtk
import numpy as np

class MultifurcationRepairTool():
	'''
	This tool works in tandem with swcToolkit to replace multifurcations (3+) in swc morphologies with bifurcations. The general method is to iteratively add very small sections to the end of the parent branch and move branches #'s 3+ to the end of the new section. This is done recursively throughout the entire tree until no multifurcations remain. 
	
	The class is generally used as follows:
	
	```
	import pandas as pd
	from roots.swcToolkit import swcToolkit
	import numpy as np
	
	#import swctool which is part of the larger ROOTS module
	swctool = swcToolkit()
	
	#load morphology which you wish to repair
	dat = swctool.load('/home/clayton/Desktop/Projects/ROOTS_HumanHDP/Final_arbors/STNroot_KMDD_13865_full.swc')
	
	#instantiate the MultifurcationsRepairTool
	repairtool = MultifurcationRepairTool()
	
	#repair morphology, new tree is returned
	newdat = repairtool.iterate_all_repairs(dat)
	
	#user swctool to write the new morphology back to a new swc file or overwrite the original
	swctool.to_swc(arbor=newdat,target='swcTest.swc')
	```
	
	'''
	def __init__(self):
		pass
	
	def identify_multifurcations(self,tree,depth=200):
		'''
		This method exists only to report the distribution of multifurcations in the morphology to be repaired. This method takes an swctool tree as an input and has null return.
		'''
		bifpoints = dict()
		for branch in tree.keys():
			bifpoints[branch] = tree[branch][0]
		
		unique_bifpoints = list(set(bifpoints.values()))
		bifcounts = dict(zip(unique_bifpoints,[0 for b in unique_bifpoints]))
		for bifpoint in bifpoints.values():
			bifcounts[bifpoint]+=1
		
		for i in range(3,depth):
			num = list(bifcounts.values()).count(i)
			if num > 0:
				print(f'there is (are) {num} multifurcation(s) with {i-1} children\n')
		
		return()


	def get_parent_children_structure(self,tree):
		'''
		This method takes an swctool tree as an input and returns a dictionary which containes parent branch indexes as keys and children branches as values
		'''
		structure = dict()
		for branch in tree.keys():
			structure[branch] = []
			if branch == 0:
				continue
			
			else:
				for b in list(tree.keys())[:branch]:
					if tree[branch][0] == tree[b][-1]:
						structure[b].append(branch)
		
		return(structure)


	def find_small_shift_vec(self,a,b,seg_size=10):
		'''
		This method calculates the endpoint of a seg_size long vector which extends the parent branch of the multifurcation. This method takes the start and end point of the parent branch and a seg_size (length of vector) to be returned, and returns a vector.
		'''
		vec = np.array([b[0]-a[0],b[1]-a[1],b[2]-a[2]])
		return([v*(seg_size/np.linalg.norm(vec)) for v in vec])

	def apply_small_shift_vec_to_branch(self,branch,vec):
		'''
		This method shifts a branch by a precalculated vector. Inputs are the branch to be shifted (structured according to swcToolkit load method) and a (x,y,z) vector. This method returns the shifted branch with no change in formatting.
		'''
		branch = [list(item) for item in branch]
		newbranch = []
		for pnt in branch:
			newbranch.append(tuple([pnt[0]+vec[0],pnt[1]+vec[1],pnt[2]+vec[2],pnt[3]]))
		
		return(newbranch)

	def create_new_small_branch(self,tree,new_branch_number,newbranch):
		'''
		This method adds a new small branch to the end of the parent branch of a multifurcation. This method takes a tree (swcToolkit formatted), new_branch_number (corresponding to the index of the new section - parent index +1), and the endpoints of the new branch (newbranch, structured according to swcToolkit) as inputs. This method returns a new tree with the new branch inserted.
		'''
		newtree = dict()
		below_new_branch = False
		for key in tree.keys():
			if key != new_branch_number and not below_new_branch:
				newtree[key] = tree[key]
			
			elif key != new_branch_number and below_new_branch:
				newtree[key+1] = tree[key]
			
			else:
				newtree[new_branch_number] = tree[key]
				newtree[new_branch_number+1] = newbranch
				below_new_branch = True
		
		return(newtree)


	def recursively_find_children(self,tree,structure,seedbranch):
		'''
		This method searches the structure (returned by get_parent_children_structure method) to discover any children of the parent to be shifted to the new branch (created by create_new_small_branch method). This method takes the tree, structure, and seedbranch (parent branch number) and returns a list of children branches to be shifted.
		'''
		b2shift = structure[seedbranch][2:]
		shift_len = None
		while shift_len != len(b2shift):
			shift_len = len(b2shift)
			for children in b2shift:
				b2shift = list(set(b2shift+structure[children]))
		
		return(b2shift)

	def iterate_repair(self,tree,seedbranch):
		'''
		This method executes ones iteration of multifurcation repair. This method takes the tree and parent branch of a multifurcation as inputs and returns a new tree with the multifurcation reduced by order of one and one new section at the end of the parent section specified (seedbranch, seedbranch+1). The index of all children branches increased by 1.
		'''
		print('Repairing one multifurcated branch')
		vec = self.find_small_shift_vec(tree[seedbranch][-2],tree[seedbranch][-1])
		tree = self.create_new_small_branch(tree,seedbranch,[tree[seedbranch][-1],tuple([tree[seedbranch][-1][0]+vec[0],tree[seedbranch][-1][1]+vec[1],tree[seedbranch][-1][2]+vec[2],tree[seedbranch][-1][3]])])
		toshift = self.recursively_find_children(tree,self.get_parent_children_structure(tree),seedbranch)
		for branch in toshift:
			tree[branch] = self.apply_small_shift_vec_to_branch(tree[branch],vec)
		
		return(tree)

	def are_multifurcations_in_structure(self,structure):
		'''
		This method takes a structure (generated by get_parent_children_structure) and identifies if there are multifurcations needing repair. Returns boolean.
		'''
		for branch in structure.keys():
			if len(structure[branch]) > 2:
				return(True)
		
		return(False)

	def iterate_all_repairs(self,tree):
		'''
		This method identifies and iterates over the tree until all multifurcations have been shifted/repaired. This method takes only the original tree as an input and returns a new and repaired tree.
		'''
		self.identify_multifurcations(tree)
		structure = self.get_parent_children_structure(tree)
		while self.are_multifurcations_in_structure(structure):
			for branch in structure.keys():
				if len(structure[branch]) > 2:
					tree = self._repair(tree,branch)
				
					break
			
			structure = self.get_parent_children_structure(tree)
			self.identify_multifurcations(tree)
		
		return(tree)

	def _repair(self,tree,seedbranch):
		'''
		This is a helper method to simplify iterate_all_repairs method. It takes the tree and parent branch of a multifurcation as inputs and returns a new tree with a single multifurcation reduced by order of 1.
		'''
		struc = self.get_parent_children_structure(tree)
		newdat = self.iterate_repair(tree,seedbranch)
		newstructure = self.get_parent_children_structure(newdat)
		return(newdat)


def toVTK(swc):
	vtkgen = swc2vtk.VtkGenerator()
	vtkgen.add_swc(swc)
	vtkgen.write_vtk(swc.strip('.swc')+'.vtk')


if __name__ == "__main__":
	import os
	morphs = [fname for fname in os.listdir(os.getcwd()+'/Final_checked') if 'ccf.swc' in fname]
	swctool = swcToolkit()
	repairtool = MultifurcationRepairTool()
	for morph in morphs:
		dat = swctool.load(os.getcwd()+'/Final_checked/'+morph)
		newdat = repairtool.iterate_all_repairs(dat)
		swctool.to_swc(arbor=newdat,target=os.getcwd()+'/Final_checked/'+morph.rstrip('_ccf.swc')+'_no_multi.swc')
		toVTK(os.getcwd()+'/Final_checked/'+morph.rstrip('_ccf.swc')+'_no_multi.swc')

