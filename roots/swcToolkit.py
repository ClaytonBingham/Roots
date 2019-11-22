import numpy as np
import math
import pandas as pd
import os
import pickle
import copy
import sys
from scipy.spatial.distance import cdist
from scipy.spatial.transform import Rotation

class swcToolkit():
	"""
	
	```
	from roots.swcToolkit import swcToolkit
	swctool = swcToolkit()
	morph1 = swctool.load(morph1_filename)
	morph2 = swctool.load(morph2_filename)
	morph3 = swctool.combine_morphologies(morph1,morph2)
	swctool.to_swc(morph3,'morph3.swc')
	```
	
	"""
	def __init__(self):
		pass
	
	def shift_point(self,a,vec):
		"""
		
		Shift a point around an origin according to user specified vector
		
		a - point to be shifted
		vector - x,y,z values to shift point by
		
		returns the shifted point
		
		"""
		
		return([a[0]-vec[0],a[1]-vec[1],a[2]-vec[2]])
	
	def move_morphology(self,arbor,vector): #unit - microns
		"""
		
		Shift a morphology around an origin according to user specified vector
		
		arbor - dictionary with branch number as keys and sections as values (each section is a list of points)
		vector - x,y,z values to shift all points by
		
		returns the shifted morphology
		
		"""
		if any(isinstance(i, list) for i in arbor[0]):
			for branch in arbor.keys():
				for section in arbor[branch]:
					arbor[branch][arbor[branch].index(section)] = [self.shift_point(point[:3],vector)+[point[-1]] for point in section]
		
		else:
			for branch in arbor.keys():
				arbor[branch]= [self.shift_point(point[:3],vector)+[point[-1]] for point in arbor[branch]]
		
		return(arbor)
	
	def rotate_points(self,origin, points, el=0.0,az=0.0):
		"""
		
		Rotate a point counterclockwise by a given angle around a given origin.
		The angle should be given in radians.
		
		"""
		r = Rotation.from_rotvec(np.array([el,az,0]))
		rotated_points = np.array(origin) - np.array(points)
		rotated_points = r.apply(rotated_points)
		return(rotated_points+np.array(origin))
	
	def rotate_morphology(self,arbor,origin,elevation=0.0,azimuth=0.0): 
		"""
		
		Rotate a morphology around an origin according to user specified elevation and azimuth
		
		arbor - dictionary with branch number as keys and sections as values (each section is a list of points)
		origin - point about which to rotate the morphology
		elevation - x,y plane in degrees
		azimuth - x,z plane in degrees
		
		returns the rotated morphology
		
		"""
		newarbor = {}
		pts = []
		if any(isinstance(i, list) for i in arbor[0]):
			for branch in arbor.keys():
				for section in arbor[branch]:
					for pt in section:
						pts.append(pt[:3])
			
			rotated_points = self.rotate_points(origin,np.array(pts),el=np.pi*elevation/180.0,az=np.pi*azimuth/180.0)
			pt_index = 0
			for branch in arbor.keys():
				newarbor[branch] = []
				for section in arbor[branch]:
					newarbor[branch].append([])
					for pt in section:
						newarbor[branch][-1].append(list(rotated_points[pt_index])+[pt[3]])
						pt_index+=1
		
		else:
			for branch in arbor.keys():
				for pt in arbor[branch]:
					pts.append(pt[:3])
			
			rotated_points = self.rotate_points(origin,np.array(pts),el=np.pi*elevation/180.0,az=np.pi*azimuth/180.0)
			pt_index = 0
			for branch in arbor.keys():
				newarbor[branch] = []
				for pt in arbor[branch]:
					newarbor[branch].append(list(rotated_points[pt_index])+[pt[3]])
					pt_index+=1
		
		
		return(newarbor)
	
	
	def split_branch_at_bifurcation(self,branch,b_point):
			return(branch[:branch.index(b_point)],branch[branch.index(b_point):])
	
	def reorder_arbor(self,arbor,a,b,c):
		newarbor = {}
		newbranch_count = 0
		for branch in arbor.keys():
			if arbor[branch] == a:
				newarbor[newbranch_count] = b
				newbranch_count+=1
				newarbor[newbranch_count] = c
				newbranch_count+=1
			else:
				newarbor[newbranch_count] = arbor[branch]
				newbranch_count+=1
		
		return(newarbor)
	
	def find_branch_w_bifurcation_point(self,arbor,b_point):
		for branch in arbor.keys():
			if b_point in arbor[branch][1:-1]:
				print(branch)
				return(branch)
		
		print(None)
		return(None)
	
	def split_branches_at_bifurcations(self,arbor):
		b_points = [arbor[b][0] for b in arbor.keys()]
#		new_arbor = copy.deepcopy(arbor)
		for point in b_points:
			a = self.find_branch_w_bifurcation_point(arbor,point)
			if a is not None:
				a = arbor[a]
			
			else:
				continue
			
			b,c = self.split_branch_at_bifurcation(a,point)
			arbor = self.reorder_arbor(arbor,a,b,c)
		return(arbor)
	
	def prepend_headers(self,filename):
		with open(filename,'r',encoding='utf-8') as f:
			dat = f.readlines()
			if dat[0] == 'n T x y z R P\n':
				return()
		with open(filename,'w',encoding='utf-8') as f:
			f.write('n T x y z R P\n')
			for line in dat:
				f.write(line)
				
	
	def cut_headers(self,filename):
		with open(filename,'r',encoding='utf-8') as f:
			dat = f.readlines()
		if dat[0] == 'n T x y z R P\n':			
			with open(filename,'w',encoding='utf-8') as f:
				for line in dat[1:]:
					f.write(line)
			return()
		else:
			return()
	
	def sort_index(self,li):
		newli = sorted(li)
		return([li.index(l) for l in newli])
	
	def find_children(self,bif,np_dict):
		children = []
		for n in np_dict.keys():
			if np_dict[n] == bif:
				children.append(n)
		return(children)
	
	def load(self,fname,asTree=True,interbifurcated=True):
		self.prepend_headers(fname)
		dat = pd.read_table(fname,delim_whitespace=True)
		self.cut_headers(fname)
		for col in ['n','T','P']:
			dat[col] = dat[col].astype('int')
		for col in ['x','y','z','R']:
			dat[col] = dat[col].astype('float')
	
		
		if asTree:
			if not interbifurcated:
				arbor = {}
				n_point = dict(zip(dat['n'],zip(dat['x'],dat['y'],dat['z'],dat['R'])))
				np_dict = dict(zip(dat['n'],dat['P']))
				branchnumber = 0
				arbor[0] = [n_point[1]]
				for n in np_dict.keys():
					if np_dict[n] == -1:
						continue
					if np_dict[n] != n-1:
						branchnumber+=1
						arbor[branchnumber] = [n_point[np_dict[n]]]
					
					arbor[branchnumber].append(n_point[n])
				
				
				return(arbor)
			
			else:
				arbor = {}
				n_point = dict(zip(dat['n'],zip(dat['x'],dat['y'],dat['z'],dat['R'])))
				np_dict = dict(zip(dat['n'],dat['P']))
				branchnumber = 0
				arbor[0] = [n_point[1]]
				for n in np_dict.keys():
					if np_dict[n] == -1:
						continue
					if np_dict[n] != n-1:
						branchnumber+=1
						arbor[branchnumber] = [np_dict[n]]
					
					arbor[branchnumber].append(n)
				
				terminals = [arbor[b][-1] for b in arbor.keys()]
				
				arbor = {}
				pn_dict = dict(zip(dat['P'],dat['n']))
				p_point = dict(zip(dat['P'],zip(dat['x'],dat['y'],dat['z'],dat['R'])))
				branchnumber = 0
				bifrows = [1]
				for n in np_dict.keys():
					if n == 1:
						continue
					if np_dict[n] != n-1:
						bifrows.append(np_dict[n])
				
				bifrows.sort()
				children = {}
				for b in bifrows:
					children[b] = self.find_children(b,np_dict)
				
				for childs in children.values():
					for child in childs:
						arbor[branchnumber] = [np_dict[child],child]
						branchnumber+=1
				
				for n,row in enumerate(dat['n']):
					if row-1 not in terminals and row-1 not in bifrows:
						for branch in arbor.keys():
							if np_dict[row] == arbor[branch][-1]:
								arbor[branch].append(row)
								break
				
				for branch in arbor.keys():
					arbor[branch] = [n_point[n] for n in arbor[branch]]
				
				
				return(arbor)
		
		else:
			x = {0:[dat['x'][0]]}
			y = {0:[dat['y'][0]]}
			z = {0:[dat['z'][0]]} 
			r = {0:[dat['R'][0]]}
			
			
			for p,point in enumerate(dat['x'][1:]):
				inc = dat['P'][p+1]
				if inc != dat['n'][p]:
					bnum = len(x.keys())
					x[bnum] = [dat.query('n == '+str(dat['P'][p+1]))['x'].values[0],dat['x'][p+1]]
					y[bnum] = [dat.query('n == '+str(dat['P'][p+1]))['y'].values[0],dat['y'][p+1]]
					z[bnum] = [dat.query('n == '+str(dat['P'][p+1]))['z'].values[0],dat['z'][p+1]]
					r[bnum] = [dat.query('n == '+str(dat['P'][p+1]))['R'].values[0],dat['R'][p+1]]
					continue
				else:
					bnum = len(x.keys())-1
					x[bnum].append(dat['x'][p+1])
					y[bnum].append(dat['y'][p+1])
					z[bnum].append(dat['z'][p+1])
					r[bnum].append(dat['R'][p+1])
			return(x,y,z,r)
	
	
	def to_swc(self,arbor=[],target='swcTest.swc'):
		
		"""
		n T x y z R P
		
		n is an integer label that identifies the current point and increments by one from one line to the next.
		
		T is an integer representing the type of neuronal segment, such as soma, axon, apical dendrite, etc. The standard accepted integer values are given below.
		
			0 = undefined
			1 = soma
			2 = axon
			3 = dendrite
			4 = apical dendrite
			5 = fork point
			6 = end point
			7 = custom
		
		x, y, z gives the cartesian coordinates of each node.
		
		R is the radius at that node.
		P indicates the parent (the integer label) of the current point or -1 to indicate an origin (soma). 
		"""
		
		try:
			with open(target,'wb') as f:
				points = [arbor[0][0]]
				n = [1]
				T = 2
				R = 0.7
				P = [-1]
				nind = 2
				Pind = 1
				f.write(str(n[-1])+' '+str(T)+' '+str(points[0][0])+' '+str(points[0][1])+' '+str(points[0][2])+' '+str(R)+' '+str(P[-1]))
				f.write('\n')
				for key in arbor.keys():
					for p,point in enumerate(arbor[key][1:]):
						points.append(point)
						n.append(nind)
						if p == 0 and key is not 0:
							P.append(points.index(arbor[key][0])+1)
						else:
							P.append(Pind)
						nind+=1
						Pind+=1
						f.write(str(n[-1])+' '+str(T)+' '+str(point[0])+' '+str(point[1])+' '+str(point[2])+' '+str(R)+' '+str(P[-1]))
						f.write('\n')
		
		except:
			with open(target,'w',encoding='utf-8') as f:
				points = [arbor[0][0]]
				n = [1]
				T = 2
				R = 0.1
				P = [-1]
				nind = 2
				Pind = 1
				f.write(str(n[-1])+' '+str(T)+' '+str(points[0][0])+' '+str(points[0][1])+' '+str(points[0][2])+' '+str(R)+' '+str(P[-1]))
				f.write('\n')
				for key in arbor.keys():
					for p,point in enumerate(arbor[key][1:]):
						points.append(point)
						n.append(nind)
						if p == 0 and key is not 0:
							P.append(points.index(arbor[key][0])+1)
						else:
							P.append(Pind)
						nind+=1
						Pind+=1
						f.write(str(n[-1])+' '+str(T)+' '+str(point[0])+' '+str(point[1])+' '+str(point[2])+' '+str(R)+' '+str(P[-1]))
						f.write('\n')
	
	def find_best_merge_point(self,a,b):
		points_a = []
		for branch in a.keys():
			points_a+=a[branch]
		
		points_a = np.array([np.array(item[:3]) for item in points_a]).reshape(len(points_a,3))
		
		points_b = []
		for branch in b.keys():
			points_b+=b[branch]
		
		points_b = np.array([np.array(item[:3]) for item in points_b]).reshape(len(points_b,3))
		
		distances = cdist(points_a,points_b)
		return(points_a[distances.argmin()])
	
	
	
	def combine_morphologies(self,a,b,merge_point=None):
		if merge_point == None:
			b[0] = self.find_best_merge_point(a,b)+b[0]
		else:
			b[0] = merge_point+b[0]
		
		for branchnumber in b.keys():
			a[len(a.keys())+branchnumber] = b[branchnumber]
		
		return(a)


