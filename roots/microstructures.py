from scipy.interpolate import interp1d
import numpy as np
import math
import os
import random
from shapely.geometry import LineString, MultiPoint
from shapely.ops import split
from shapely import wkt
from scipy.spatial.distance import cdist

class Microstructures():
	"""
	A class to add microstructures such as boutons and myelin to an axon morphology
	
	```
	from roots.microstructures import Microstructures
	mstruct = Microstructures()
	mstruct.primarytest()
	arbor = {}
	arbor[0] = [[0,0,0],[1,0,0],[2,0,0]]
	mstruct.add_microstructures_to_arbor(arbor,mbranches,bbranches)
	```
	
	"""
	
	def __init__(self):
		pass
	
	def apply_microstructures_diameter_scalars(self,arbor,arbor_labels,label_scalars={},replace=True):
		if label_scalars == {}:
			print('didn\'t do any scaling because label_scalars=={}')
			return(arbor)
		
		if replace:
			for branch in arbor.keys():
				for s,section in enumerate(arbor[branch]):
					arbor[branch][s] = [list(item[:-1])+[label_scalars[arbor_labels[branch][s]]] for item in arbor[branch][s]]
		
		else:
			for branch in arbor.keys():
				for s,section in enumerate(arbor[branch]):
					arbor[branch][s] = [list(item[:-1])+[label_scalars[arbor_labels[branch][s]]*item[-1]] for item in arbor[branch][s]]
		
		return(arbor)
	
	def eucdist3d(self,point1,point2):
		"""
		
		euclidean distance between point1 and point2 - [x,y,z]
		
		"""
#		if not isinstance(point1,np.ndarray):
#			point1 = np.array(point1)
#			point2 = np.array(point2)
		
		return(((point2[0]-point1[0])**2 + (point2[1]-point1[1])**2 + (point2[2]-point1[2])**2)**0.5)
	
	def branchLength(self,branch):
		"""
		
		branch - list of points comprising a branch
		returns - the path length of the branch
		
		
		"""
		
		length = 0
		for p,point in enumerate(branch[:-1]):
			length+=self.eucdist3d(branch[p],branch[p+1])
		
		return(length)
	
	def parse_spline(self,shapelystring):
		st = wkt.loads(shapelystring)
#		sl = np.array(st[0])
#		if len(st) > 1:
#			for s in st[1:]:
#				sl = np.append(sl,np.array(s),axis=0)
	
		return([list(point) for point in np.array(st)])
	
	def reassign_diameters(self,original,new):
		complist = [p[:3] for p in original]
		for n,point in enumerate(new):
			new[n].append(original[np.argmin(cdist([list(point)],complist))][-1])
		
		return(new)
	
	def spline_branch(self,branch,interval=1.0):
		"""
		
		Spline branch to evenly spread points to make re-sectioning by myelin or boutons easier
		
		branch - list of points comprising a branch
		interval - maximum distance between points in newly splined branch
		
		"""
		
		number_of_points = int(round(self.branchLength(branch)/interval,0))+1
		line = LineString([tuple(point[:3]) for point in branch])
		splitter = MultiPoint([line.interpolate((i/number_of_points),normalized=True) for i in range(number_of_points+1)])
		interp = self.parse_spline(splitter.wkt)
		#interp = [list(branch[0][:3])] + interp[1:] + [list(branch[-1][:3])]
		return(self.reassign_diameters(branch,interp))
#		
#		x = [pnt[0] for pnt in branch]
#		y = [pnt[1] for pnt in branch]
#		z = [pnt[2] for pnt in branch]
#		r = [pnt[3] for pnt in branch]
#		newx = np.linspace(0,len(x)-1,num=number_of_points,endpoint=True)
#		newy = np.linspace(0,len(y)-1,num=number_of_points,endpoint=True)
#		newz = np.linspace(0,len(z)-1,num=number_of_points,endpoint=True)
#		newr = np.linspace(0,len(r)-1,num=number_of_points,endpoint=True)
#		if len(x) < 4:
#			if len(x) < 3:
#				order = 'linear'
#			
#			else:
#				order = 'quadratic'
#		else:
#			order = 'cubic'
#		
#		fx = interp1d(range(len(x)),x,kind=order)
#		fy = interp1d(range(len(y)),y,kind=order)
#		fz = interp1d(range(len(z)),z,kind=order)
#		fr = interp1d(range(len(r)),r,kind=order)
#		return(list(zip(fx(newx),fy(newy),fz(newz),fr(newr))))
	
	def find_optimal_segmentation_length(self,blength,seg_range):
		"""
		
		blength - length of the branch in microns
		seg_range - acceptable range of lengths for node+paranode1+paranode2+internode+paranode2+paranode1 length (as a unit of myelination) or interbouton+bouton length (as a unit of bouton size)
		returns - a list of segment lengths that optimally divides a branch into myelinated/boutoned regions
		
		"""
		seg_range = self.generate_seg_range(seg_range)
		easiestfit = seg_range[0]
		remainder = np.max(seg_range)
		for segr in seg_range:
			remains = blength - math.floor(blength/segr)*segr
			if remains<remainder:
				remainder=remains
				easiestfit=segr
		
		seg_lengths = [easiestfit for i in range(math.floor(blength/easiestfit))]
		return([segment+remainder/len(seg_lengths) for segment in seg_lengths])
	
	def divide_microstructure_unit(self,point1,point2,dimensions):
		"""
		
		point1 - beginning of region to be resegmented
		point2 - end of region to be resegmented
		dimensions - lengths to cut region
		returns - new segments that make up the microstructure being added to the region
		
		"""
		new_sections = []
		if len(point1) < 4:
			done = 0.0
			dtwo = 0.0
		else:
			done = point1[-1]
			dtwo = point2[-1]
		
		p1 = np.array(point1[:3])
		p2 = np.array(point2[:3])
		vec = p2-p1
		dimslength = float(np.sum(dimensions))
		for d,dim in enumerate(dimensions[:-1]):
			nearsideproportion = np.sum(dimensions[:d])/dimslength
			farsideproportion = np.sum(dimensions[:d+1])/dimslength
			new_sections.append([	
						list(np.append(p1+vec*nearsideproportion,done)),
						list(np.append(((p1+vec*nearsideproportion)+(p1+vec*farsideproportion))/2.0,(done+dtwo)/2.0)),
						list(np.append(p1+vec*farsideproportion,dtwo))
						])
		
		new_sections.append([	
					list(new_sections[-1][-1]),
					list((np.array(new_sections[-1][-1])+np.array(list(point2[:3])+[dtwo]))/2.0),
					list(point2[:3])+[dtwo]
					])
		
		if len(dimensions) > 2:
			return(new_sections,['node','paranode1','paranode2','internode','paranode2','paranode1'][:len(new_sections)])
		
		else:
			return(new_sections,['interbouton','bouton'][:len(new_sections)])
	
	def generate_seg_range(self,length):
		return(np.arange(length*0.75,length*1.25,0.1))
	
	def myelinate_branch(self,branch,myelin_dimensions):
		"""
		This function finds optimal microstructure dimensions to fit within a user specified branch, 
		redistributes points through the branch corresponding to the breakpoitns of these section,
		and returns the end points of each of these new structures.
		
		branch - list of points comprising a branch
		myelin_dimensions - descriptions of node, paranode1,paranode2, and internode lengths (microns)
		returns - branch where list members are end points of each new section
		
		"""
		
		try:
			segments = self.find_optimal_segmentation_length(self.branchLength(branch),seg_range=np.sum(myelin_dimensions))
		except:
			return(self.segment_and_label_branch(branch,'node'))
		
		if segments == []:
			return(self.segment_and_label_branch(branch,'node'))
		
		try:
			splined_branch = self.spline_branch(branch,interval=segments[0])
		except:
			return(self.segment_and_label_branch(branch,'node'))
		
		segmented_branch = []
		labellist = []
		for s,segment in enumerate(splined_branch[:-1]):
			microstructure,labels=self.divide_microstructure_unit(splined_branch[s],splined_branch[s+1],myelin_dimensions[:3]+[self.branchLength(splined_branch)/len(segments) - np.sum(myelin_dimensions[:3])-np.sum(myelin_dimensions[4:])]+myelin_dimensions[4:])
			segmented_branch+=microstructure
			labellist+=labels
		
		del(myelin_dimensions)
		return(segmented_branch,labellist)
	
	def myelinate_branches(self,arbor,arbor_labels,mbranches,myelin_geometry=[1,1,3,8,3,1]):
		
		"""
		mbranches - branch indices in arbor to be myelinated
		myelin_dimensions - node length, paranode1 length, paranode2 length, internode (between paranodes) length
		return(arbor,labels)
		
		"""
		
		for branch in arbor.keys():
			if branch in mbranches:
				arbor[branch],arbor_labels[branch] = self.myelinate_branch(arbor[branch],myelin_geometry)
		
		return(arbor,arbor_labels)
	
	def insert_midpoint(self,a,b):
		midpoint = [item/2.0 for item in [a[0]+b[0],a[1]+b[1],a[2]+b[2],a[3]+b[3]]]
		return([list(a),midpoint,list(b)])
	
	def segment_and_label_branch(self,branch,label):
		if len(branch) < 3:
			newbranch = [self.insert_midpoint(branch[0],branch[-1])]
			return(newbranch,[label for i in range(len(newbranch))])
		
		else:
			return([self.insert_midpoint(branch[i],branch[i+1]) for i in range(len(branch[:-1]))],[label for i in range(len(branch[:-1]))])
	
	def bouton_branch(self,branch,bouton_dimensions):
		"""
		This function finds optimal microstructure dimensions to fit within a user specified branch, 
		redistributes points through the branch corresponding to the breakpoitns of these section,
		and returns the end points of each of these new structures.
		
		branch - list of points comprising a branch
		bouton_dimensions - descriptions of interbouton and bouton lengths (microns)
		returns - branch where list members are end points of each new section
		
		"""
		try:
			segments = self.find_optimal_segmentation_length(self.branchLength(branch),seg_range=np.sum(bouton_dimensions))
		except:
			return(self.segment_and_label_branch(branch,'interbouton'))
		
		if segments == []:
			return(self.segment_and_label_branch(branch,'interbouton'))
		
		try:
			splined_branch = self.spline_branch(branch,interval=segments[0])
		except:
			return(self.segment_and_label_branch(branch,'interbouton'))
		
		
		segmented_branch = []
		labellist = []
		for s,segment in enumerate(splined_branch[:-1]):
			microstructure,labels = self.divide_microstructure_unit(splined_branch[s],splined_branch[s+1],[self.branchLength(splined_branch)/len(segments) - bouton_dimensions[1],bouton_dimensions[1]])
			segmented_branch+=microstructure
			labellist+=labels
		
		del(bouton_dimensions)
		return(segmented_branch,labellist)
	
	
	def bouton_branches(self,arbor,arbor_labels,bbranches,bouton_geometry=[28,4]):
		"""
		
		bbranches - branch indices in arbor to be myelinated
		bouton_dimensions - (interbouton length upper and lower bounds), bouton length
		return(arbor,labels)
		
		"""
		
		for branch in arbor.keys():
			if branch in bbranches:
				arbor[branch],arbor_labels[branch] = self.bouton_branch(arbor[branch],bouton_geometry)
		
		return(arbor,arbor_labels)
	
	def calculate_start_middle_distances(self,point,newbranch):
		startdistances = []
		middledistances = []
		for section in newbranch:
			try:
				startdistances.append(self.eucdist3d(point,section[0]))
				middledistances.append(self.eucdist3d(point,section[1]))
			except:
				raise Exception(point,section,'couldnt calculate distance',newbranch)
		
		return(startdistances,middledistances)
	
	def add_back_branch_point(self,point,newbranch,labels):
		#find nearest section and nearest two points in section and insert b_point between them
		start,middle = self.calculate_start_middle_distances(point,newbranch)
		min_dist = np.max(middle)
		found = False
		for distance in zip(start,middle):
			if distance[1] < distance[0] and distance[0] < min_dist:
				min_dist = distance[1]
				found=True
		
		print(found,min_dist,'mindist',point,newbranch[middle.index(min_dist)])
		
#		if np.min(middle) > 40.0:
#			return(newbranch)
		
		split_branch = []
		split_labels = []
		if found:
			section_index = middle.index(min_dist)
		else:
			section_index = middle.index(np.min(middle))
		
		for s,section in enumerate(newbranch):
			if s == section_index:
				split_branch.append(self.insert_midpoint(section[0],point))
				split_branch.append(self.insert_midpoint(point,section[2]))
				split_labels.append(labels[s])
				split_labels.append(labels[s])
			else:
				split_branch.append(section)
				split_labels.append(labels[s])
		
#		if found:
#			newbranch[middle.index(min_dist)][1] = list(point)[:3] + [newbranch[middle.index(min_dist)][0][-1]]
#		else:
#			newbranch[middle.index(np.min(middle))][1] = list(point)[:3] + [newbranch[middle.index(min_dist)][0][-1]]
		
		
		
		return(newbranch,labels)
	
	def add_back_branch_points(self,originaltree,newtree,newlabels):
		b_points = [originaltree[b][0] for b in originaltree.keys()][1:]
		bbs = [b for b in originaltree.keys()][1:]
		for point in b_points:
			for branch in originaltree.keys():
				if branch == bbs[b_points.index(point)]:
					continue
				
				if point in originaltree[branch]:
					newtree[branch],newlabels[branch] =self.add_back_branch_point(point,newtree[branch],newlabels[branch])
		
		return(newtree,newlabels)
	
	def ensure_precision(self,arbor):
		for branch in arbor.keys():
			for s,section in enumerate(arbor[branch]):
				for p,point in enumerate(section):
					arbor[branch][s][p] = [round(item,4) for item in point]
		
		return(arbor)
	
	def add_microstructures_to_arbor(self,arbor,mbranches,bbranches):
		"""
		
		This function adds myelin and boutons to an axon arbor. 
		
		arbor - dictionary where keys are branch numbers and values are points comprising each branchLength
		mbranches - branch indices found in arbor where branches are expected to contain myelin_dimension
		bbranches - branch indices found in arbor where branches are expected to have en passant boutons
		
		returns: newly myelinated or boutoned arbor, and mirror dictionary with descriptive labels for all sections
		
		"""
		arbor_labels = dict(zip([key for key in arbor.keys()],[[] for key in arbor.keys()]))
		arbor,arbor_labels = self.myelinate_branches(arbor,arbor_labels,mbranches)
		arbor,arbor_labels = self.bouton_branches(arbor,arbor_labels,bbranches)
		arbor = self.ensure_precision(arbor)
		return(arbor,arbor_labels)
	
	def testfuncs(self):
		if self.eucdist3d((0,0,0),(1,0,0)) == 1.0:
			print('eucdist3d()--passed simple test')
		
		else:
			print('eucdist3d()--failed simple test')
		
		if self.branchLength([(0,0,0),(1,0,0)]) == 1.0:
			print('branchLength()--passed simple test')
		
		else:
			print('eucdist3d()--failed simple test')
		
		if self.spline_branch([(0,0,0),(1,0,0)],interval=0.5)==[(0,0,0),(0.5,0,0),(1,0,0)]:
			print('spline_branch()--passed simple test')
		
		else:
			print('eucdist3d()--failed simple test')
		
		if self.find_optimal_segmentation_length(112.215)[0] == 18.7025:
			print('find_optimal_segmentation_length()--passed simple test')
		
		else:
			print('find_optimal_segmentation_length()--failed simple test')
		
		sections,labels = self.divide_microstructure_unit([0,0,0],[10,0,0],[5,5])
		if sections == [[[0.0, 0.0, 0.0], [2.5, 0.0, 0.0], [5.0, 0.0, 0.0]], [[5.0, 0.0, 0.0], [7.5, 0.0, 0.0], [10, 0, 0]]]:
			print('divide_microstructure_unit() -boutons- --passed simple test')
		
		else:
			print('divide_microstructure_unit() -boutons- --failed simple test')
		
		sections,labels = self.divide_microstructure_unit([0,0,0],[19,0,0],[1,1,3,10,3,1])
		if sections == [[[0.0, 0.0, 0.0], [0.5, 0.0, 0.0], [1.0, 0.0, 0.0]], [[1.0, 0.0, 0.0], [1.5, 0.0, 0.0], [2.0, 0.0, 0.0]], [[2.0, 0.0, 0.0], [3.5, 0.0, 0.0], [5.0, 0.0, 0.0]], [[5.0, 0.0, 0.0], [10.0, 0.0, 0.0], [15.0, 0.0, 0.0]], [[15.0, 0.0, 0.0], [16.5, 0.0, 0.0], [18.0, 0.0, 0.0]], [[18.0, 0.0, 0.0], [18.5, 0.0, 0.0], [19, 0, 0]]]:
			print('divide_microstructure_unit() -myelin- --passed simple test')
		
		else:
			print('divide_microstructure_unit() -myelin- --failed simple test')
		
		branch,labels = self.myelinate_branch([[0,0,0],[100,0,0]])
		
		if branch == [[[0.0, 0.0, 0.0], [0.5, 0.0, 0.0], [1.0, 0.0, 0.0]], [[1.0, 0.0, 0.0], [1.5, 0.0, 0.0], [2.0, 0.0, 0.0]], [[2.0, 0.0, 0.0], [3.5, 0.0, 0.0], [5.0, 0.0, 0.0]], [[5.0, 0.0, 0.0], [17.166666666666664, 0.0, 0.0], [29.33333333333333, 0.0, 0.0]], [[29.33333333333333, 0.0, 0.0], [30.83333333333333, 0.0, 0.0], [32.33333333333333, 0.0, 0.0]], [[32.33333333333333, 0.0, 0.0], [32.83333333333333, 0.0, 0.0], [33.33333333333333, 0.0, 0.0]], [[33.33333333333333, 0.0, 0.0], [33.83333333333333, 0.0, 0.0], [34.33333333333333, 0.0, 0.0]], [[34.33333333333333, 0.0, 0.0], [34.83333333333333, 0.0, 0.0], [35.33333333333333, 0.0, 0.0]], [[35.33333333333333, 0.0, 0.0], [36.83333333333333, 0.0, 0.0], [38.33333333333333, 0.0, 0.0]], [[38.33333333333333, 0.0, 0.0], [50.49999999999999, 0.0, 0.0], [62.66666666666666, 0.0, 0.0]], [[62.66666666666666, 0.0, 0.0], [64.16666666666666, 0.0, 0.0], [65.66666666666666, 0.0, 0.0]], [[65.66666666666666, 0.0, 0.0], [66.16666666666666, 0.0, 0.0], [66.66666666666666, 0.0, 0.0]], [[66.66666666666666, 0.0, 0.0], [67.16666666666666, 0.0, 0.0], [67.66666666666666, 0.0, 0.0]], [[67.66666666666666, 0.0, 0.0], [68.16666666666666, 0.0, 0.0], [68.66666666666666, 0.0, 0.0]], [[68.66666666666666, 0.0, 0.0], [70.16666666666666, 0.0, 0.0], [71.66666666666666, 0.0, 0.0]], [[71.66666666666666, 0.0, 0.0], [83.83333333333333, 0.0, 0.0], [96.0, 0.0, 0.0]], [[96.0, 0.0, 0.0], [97.5, 0.0, 0.0], [99.0, 0.0, 0.0]], [[99.0, 0.0, 0.0], [99.5, 0.0, 0.0], [100.0, 0.0, 0.0]]]:
			print('myelinate_branch() --passed simple test')
		
		else:
			print('myelinate_branch() --failed simple test')
		
		branch,labels = self.bouton_branch([[0,0,0],[100,0,0]],bouton_dimensions=[(15,20),5])
		
		if branch == [[[0.0, 0.0, 0.0], [7.5, 0.0, 0.0], [15.0, 0.0, 0.0]], [[15.0, 0.0, 0.0], [17.5, 0.0, 0.0], [20.0, 0.0, 0.0]], [[20.0, 0.0, 0.0], [27.5, 0.0, 0.0], [35.0, 0.0, 0.0]], [[35.0, 0.0, 0.0], [37.5, 0.0, 0.0], [40.0, 0.0, 0.0]], [[40.0, 0.0, 0.0], [47.5, 0.0, 0.0], [55.00000000000001, 0.0, 0.0]], [[55.00000000000001, 0.0, 0.0], [57.50000000000001, 0.0, 0.0], [60.00000000000001, 0.0, 0.0]], [[60.00000000000001, 0.0, 0.0], [67.5, 0.0, 0.0], [75.0, 0.0, 0.0]], [[75.0, 0.0, 0.0], [77.5, 0.0, 0.0], [80.0, 0.0, 0.0]], [[80.0, 0.0, 0.0], [87.5, 0.0, 0.0], [95.0, 0.0, 0.0]], [[95.0, 0.0, 0.0], [97.5, 0.0, 0.0], [100.0, 0.0, 0.0]]]:
			print('bouton_branch() --passed simple test')
		
		else:
			print('bouton_branch() --failed simple test')


