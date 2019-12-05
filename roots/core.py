import numpy as np
import math
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import random
from scipy.interpolate import interp1d
import scipy
import time
from roots.graphmethods import GraphMethods
from roots.kmd import KMDD
#import seaborn as sns
#plt.style.use('seaborn-deep')
#import matplotlib
#matplotlib.rcParams.update({'font.size': 32})
import os
random.seed("clayton\'s warhorse")
import traceback
from itertools import chain
#from colormap import Colormap
#c = Colormap()
#mycmap = c.cmap_linear('yellow','orange','red')


class Analyze_roots():
	def __init__(self,roots):
		self.roots = roots
		self.math = Roots_math()
		self.centroid = self.find_centroid()
		self.xyz_dist()
		self.internodedist_dist()
		self.branchnodes = [self.roots[node][0] for node in self.roots.keys()]
		self.seconds = [self.roots[node][1] for node in self.roots.keys()]
		self.thetas = self.bifurcation_thetas()
	
	def find_branch_parent(self,firstpoint,ownbnum):
		for brnum in self.roots.keys():
			if brnum != ownbnum and firstpoint in self.roots[brnum]:
				try:
					return(self.roots[brnum][self.roots[brnum].index(firstpoint)+1]) 
				except:
					print('parent not found',end="\r", flush=True)
					return(None)

	def find_branch_angle(self,firstpoint,firstpointsecond,secondsecond):	
		pointpresent = np.array(firstpoint)
		pointnext = np.array(firstpointsecond)
		pointlast = np.array(secondsecond)
		return(np.dot(pointlast-pointpresent,pointnext-pointpresent)/(self.math.eucdist3d(pointpresent,pointnext)*self.math.eucdist3d(pointpresent,pointlast)))
	
	
	def find_centroid(self):
		x,y,z = 0,0,0
		for i,key in enumerate(self.roots.keys()):
			for point in self.roots[key]:
				x+=point[0]
				y+=point[1]
				z+=point[2]
		return([x/float(i),y/float(i),z/float(i)])
	
	def xyz_dist(self):
		self.xdist,self.ydist,self.zdist = [],[],[]
		for i,key in enumerate(self.roots.keys()):
			for point in self.roots[key]:
				self.xdist.append(self.centroid[0] - point[0])
				self.ydist.append(self.centroid[1] - point[1])
				self.zdist.append(self.centroid[2] - point[2])
		ax = sns.distplot(np.array(self.xdist),kde=True, rug=True,label='X KDE', hist=False,kde_kws={"shade": True})
		ax = sns.distplot(np.array(self.ydist),kde=True, rug=True,label='Y KDE',hist=False,kde_kws={"shade": True})
		ax = sns.distplot(np.array(self.zdist),kde=True, rug=True, label='Z KDE',hist=False,kde_kws={"shade": True})
		plt.legend()
		plt.title('KDEs of Spatial Range of Arbor Relative to Centroid')
		plt.show()
	
	def bifurcation_thetas(self):
		thetas = []
		for n,node in enumerate(self.branchnodes):
			try:
				first,second,secondsecond = node,self.roots[n][1],self.find_branch_parent(node,n)
				#print(first,second,secondsecond)
				thetas.append(self.find_branch_angle(node,self.roots[n][1],self.find_branch_parent(node,n)))
			except:
				print('theta not found')
		ax = sns.distplot(np.abs(np.array(thetas)),kde=True, rug=True,label='Bifurcation Angles KDE', hist=False,kde_kws={"shade": True})
		plt.legend()
		plt.xlabel('Angle (Radians)')
		plt.show()
	
	def internodedist_dist(self):
		dists = []
		for i,key in enumerate(self.roots.keys()):
			for j,point in enumerate(self.roots[key][1:]):
				dists.append(self.math.eucdist3d(point,self.roots[key][j-1]))
		ax = sns.distplot(np.array(dists),label='Internode Distance', kde=True, rug=True,hist=False,kde_kws={"shade": True})
		plt.legend()
		plt.xlabel('um')
		plt.show()


class Roots_math():
	def __init__(self,isKMDD=False,KMDDproperties={},preconditionedKMDD=None):
		self.isKMDD = isKMDD
		self.KMDDproperties = KMDDproperties
		if self.isKMDD:
			try:
				cluster_reduce = self.KMDDproperties['cluster_reduce']
				tri_edge_length_max = self.KMDDproperties['tri_edge_length_max']
				openpoints = self.KMDDproperties['open_points']
				source = self.KMDDproperties['source']
			except:
				raise Exception("Error with KMDDproperties argument dictionary. Must include KMDDproperties values for keys: 'cluster_reduce','tri_edge_length_max','open_points','source'.")
			
			#find spatial clusters within cloud of synaptic targets in order to simplify arbor enough to find triangulation and paths through arbor field.
			#find delaunay triangulation through kmeans clustered spatial network of cloud of synaptic targets
			self.kmdd = KMDD(source,openpoints,cluster_reduce,tri_edge_length_max)
			
			#Dijkstras algorithm to find shortest paths through network of pairs of points in delaunay triangulated kmeans clustered cloud of synaptic targets.
			self.source_index = [list(item) for item in list(self.kmdd.vertices)].index(list(source))
			self.nk = GraphMethods(self.kmdd.faces,self.kmdd.vertices,source,self.source_index,tri_edge_length_max)
			if self.nk.node_dict == {}:
				raise Exception('Likely path sort failed. Try a longer tri_edge_length_max in KMDDproperties args.')
			
			print('got graph')
			try:
				assert self.KMDDproperties['plot']
				self.kmdd.plot_clusters_and_points(self.kmdd.vertices,openpoints)
				self.kmdd.mayavi_plot_delaunay_tri(source,tri_edge_length_max)
			except:
				pass
	
	def euc_tree(self,allpoints,point):
		return([self.eucdist3d(thisp,point) for thisp in allpoints])
	
	def euc_tree_length(self,arbor):
		len = 0
		for branch in arbor.keys():
			branchpoints = arbor[branch]
			for p,point in enumerate(branchpoints[1:]):
				try:
					len+=self.eucdist3d(branchpoints[p-1],branchpoints[p])
				
				except:
					print(traceback.format_exc())
		
		return(len)
	
	def eucdist3d(self,point1,point2):
		return(((point2[0]-point1[0])**2 + (point2[1]-point1[1])**2 + (point2[2]-point1[2])**2)**0.5)

	def angle_tree(self, allpoints, point, prevpoint):
		return([np.pi - self.check_angle(point, thisp, prevpoint) for thisp in allpoints])

	def choose_nearest(self, point, allpoints):
		""" chooses closest point from a set of given points and returns the index of that point in the array and the actual point itself """
		dists = dict(zip(self.euc_tree(allpoints,point),allpoints))
		if len(dists.keys()) > 1:
			nearest = dists[min(dists.keys())]
			nearestindex = allpoints.index(nearest)
		else:
			return(point, 0)
		
		return(nearest, nearestindex)

	def choose_nearest_bif(self, point, allpoints):
		dists = dict(zip(self.euc_tree(allpoints,point),allpoints))
		nearest = dists[min(dists.keys())]
		nearestindex = allpoints.index(nearest)
		return(nearest, nearestindex)
	
	def find_point_on_arbor(self, arbor, point, branch_counter):
		""" Finds branch_counter from last key and index of point on arbor and returns that key and index """
		
		counter = branch_counter
		for key in reversed(arbor.keys()):
			for index, this_point in enumerate(arbor[key]):
				if arbor[key][index] == point:
					if counter == 0:
						return(key, index)
					counter = counter - 1
		
	
	def lookup_nearest_likely_path(self,point_of_int):
		""" Returns a point a little over the specified path length away from the branch end """
		cluster_distances = self.euc_tree(self.kmdd.vertices,point_of_int)
		sorted_distances = list(sorted(cluster_distances))
		for increasing_distance in sorted_distances:
			nearest_cluster_node = cluster_distances.index(increasing_distance)
			for key in self.nk.node_dict.keys():
				if nearest_cluster_node in self.nk.paths[self.nk.node_dict[key]]:
					nearest_path_index = self.nk.node_dict[key]
					return(nearest_cluster_node,nearest_path_index)
		
		print('No path found for this cluster point',self.kmdd.vertices[nearest_cluster_node],end="\r", flush=True)
		#print('last path considered',self.nk.paths[self.nk.node_dict[key]])
		try:
			nearest_path_index = self.nk.node_dict[key]
		except:
			#nearest_path_index = self.nk.node_dict[list(self.nk.node_dict.keys())[0]]
			nearest_path_index = 0
		#nearest_path_index = self.node_dict[nearest_cluster_node]
		return(nearest_cluster_node,nearest_path_index)
	
	def find_diff_apply_to_other(self,A,B,C):
		diff = [B[0]-A[0],B[1]-A[1],B[2]-A[2]]
		return([C[0]-diff[0],C[1]-diff[1],C[2]-diff[2]])
	
	def find_dynamic_source_point_from_likely_path(self,point_of_int):
		nearest_cluster_node,nearest_path_index = self.lookup_nearest_likely_path(point_of_int)
		nearest_node_index_in_path = self.nk.paths[nearest_path_index].index(nearest_cluster_node)
		if nearest_node_index_in_path == len(self.nk.paths[nearest_path_index])-1:
			nearest_node_index_in_path-=1
		return(self.find_diff_apply_to_other(self.kmdd.vertices[self.nk.paths[nearest_path_index][nearest_node_index_in_path]],self.kmdd.vertices[self.nk.paths[nearest_path_index][nearest_node_index_in_path+1]],point_of_int))
	
	
	def find_relative_source(self, arbor, point_of_int, rel_source_dist):
		if self.isKMDD:
			try:
				return(self.find_dynamic_source_point_from_likely_path(point_of_int))
			
			except:
				print(traceback.format_exc())
				print('\n\nContinuing as if not KMDD directed',end="\r", flush=True)
				return(arbor[0][0])
		
		else:
			return(arbor[0][0])

	
	def branch_extension_check(self, firstextend, arborpoint, prevpoint, openpoints, distthresh, angthresh, rel_source_dist, arbor):
		""" Checks whether the branch can be extended; returns true or false and the point that it should be extended with """
		rel_source = self.find_relative_source(arbor, arborpoint, rel_source_dist)
		refdist = self.eucdist3d(arborpoint, rel_source) #distance from arbor point to source	
		alldists = self.euc_tree(openpoints, rel_source) #array of distances from source to each open point
		
		filteredpoints = [openpoints[i] for i, thisdist in enumerate(alldists) if thisdist >= refdist]
		dists = dict(zip(self.euc_tree(filteredpoints, arborpoint), filteredpoints)) #dictionary of distances between branch tip and set of open points paired with open points
		
		if firstextend:	
			if min(dists.keys()) > distthresh:
				return(False, dists[min(dists.keys())])
			
			else:
				return(True, dists[min(dists.keys())])
		
		else: #finds the closest point to branch tip, to extend from
			bad_ang = True
			good_dist = True
			nextpoint = [0,0,0]
			
			while (bad_ang and good_dist and len(dists.keys()) > 0):	
				bad_ang = np.pi - self.check_angle(arborpoint, dists[min(dists.keys())], prevpoint) > angthresh
				good_dist = min(dists.keys()) <= distthresh
				nextpoint = dists.pop(min(dists.keys()))
			
			return(not(bad_ang) and good_dist > 0, nextpoint)
	
	def return_closed_points(self,arbor,source): 
		closed = [item[1:-1] for item in list(arbor.values())]
		closed = [source]+list(chain.from_iterable(closed))
		return(closed)
	
	
	def choose_first_valid_bifurcation(self, arbor, openpoint, source, angthresh, distthresh, rel_source_dist):
		openpt_rel_source = self.find_relative_source(arbor,openpoint,rel_source_dist)
		openpt_rel_source_dist = self.eucdist3d(openpoint,openpt_rel_source)
		closed = self.return_closed_points(arbor,source)
		for c_point in closed[::-1]:
			if self.eucdist3d(c_point,openpt_rel_source) < openpt_rel_source_dist:
				filteredpoint = self.filter_angle(c_point,arbor,openpoint,angthresh)
				if filteredpoint == []:
					continue
				
				else:
					print(filteredpoint)
					return(True,filteredpoint)
	
		return(False,[0,0,0])
	
	
	
	def check_angle(self, pointpresent, pointnext, pointlast):
		pointpresent = np.array(pointpresent)
		pointnext = np.array(pointnext)
		pointlast = np.array(pointlast)
		return(np.abs(math.acos(np.dot(pointlast-pointpresent,pointnext-pointpresent)/(self.eucdist3d(pointpresent,pointnext)*self.eucdist3d(pointpresent,pointlast)))))

	def filter_angles(self, filteredpoints, arbor, openpoint, angthresh):
		morefilteredpoints = [] #array for output of function
		for fpoint in filteredpoints: #goes through each point in array, checks whether it is below angle threshold, and if so, appends point to morefilteredpoints
			goodangle = True
			for key in arbor.keys():
				if fpoint in arbor[key]:
					pointfoundindex = arbor[key].index(fpoint) #finds index of the point on the arbor in that key
					if self.check_angle(fpoint, arbor[key][pointfoundindex+1], openpoint) > angthresh: #checks whether angle meets threshold
						goodangle = False
						break
			
			if goodangle:
				morefilteredpoints.append(fpoint)
		
		return(morefilteredpoints)
	
	def filter_angle(self, filteredpoint, arbor, openpoint, angthresh):
		for key in arbor.keys():
			if filteredpoint in arbor[key]:
				pointfoundindex = arbor[key].index(filteredpoint) #finds index of the point on the arbor in that key
				if self.check_angle(arbor[key][pointfoundindex-1], filteredpoint, openpoint) > angthresh: #checks whether angle meets threshold
					return([])
				
				else:
					return(filteredpoint)
		
		return([])


class Roots():
	
	"""
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
	"""
	def __init__(self, source, points,total_length=np.inf, s_ang=np.pi, s_dist=100, b_ang=np.pi, b_dist=100, bnum_limit=np.inf,rel_source_dist=100,KMDDproperties={}):
		self.KMDDproperties = KMDDproperties
		self.source = source
		self.openpoints = points
		self.tot_len_threshold = total_length
		self.bnum_limit = bnum_limit
		self.s_ang = s_ang
		self.s_dist = s_dist
		self.b_ang = b_ang
		self.b_dist = b_dist
		self.rel_source_dist = rel_source_dist
		self.allpoints = [self.source]+self.openpoints
		self.arbor = {0:[self.source]}
		self.stamps = []
		self.labels = []
		if self.KMDDproperties == {}:
			self.math = Roots_math(False,self.KMDDproperties,None)
			self.sort_points()
		
		else:
			self.math = Roots_math(True,self.KMDDproperties,None)
			self.sort_points()
		
		#self.plotroots = Roots_plot()
	
	
	def stamp(self,label):
		self.stamps.append(time.time())
		self.labels.append(label)
		
	
	def sort_points(self):
		self.stamp('sort points')
		tpoints = list(zip(self.openpoints,self.math.euc_tree(self.openpoints, self.source)))
		tpoints.sort(key= lambda x: x[1])
		self.openpoints = [tpoint[0] for tpoint in tpoints]
		self.stamp('sort points')
	
	def clean_points(self,point):
		pointindex = self.openpoints.index(point)
		self.openpoints = self.openpoints[:pointindex] + self.openpoints[pointindex+1:]
	
	def bifurcate(self,branchpoint, newpoint):
		self.arbor[len(self.arbor.keys())] = [branchpoint, newpoint] #appends new key at end of arbor as a new branch. This is an array of two points, the point previously on the arbor and a new point branching off from this point
	
	def is_acceptable_total_length(self):
		if self.calculate_total_arbor_length() > self.tot_len_threshold:
			return(False)
		
		else:
			return(True)
	
	def is_acceptable_number_of_branches(self):
		if len(self.arbor.keys()) > self.bnum_limit:
			return(False)
		
		else:
			return(True)
	
	
	def calculate_total_arbor_length(self):
		return(self.math.euc_tree_length(self.arbor))
	
	def add_to_arbor(self,newpoint):
		arborindex = max(list(self.arbor.keys()))
		self.arbor[arborindex].append(newpoint)
	
	
	def prims(self):
		arborindex = max(list(self.arbor.keys())) #last key in arbor
		number_of_points = 0
		stillextending = True
		
		while stillextending:
			if len(self.arbor[arborindex]) == 1: #initial branch extension from soma
				#goodextend, nearest = self.math.branch_extension_check(True, self.arbor[arborindex][-1], self.arbor[arborindex][-1], self.openpoints, self.s_dist, self.s_ang, self.source)
				goodextend, nearest = self.math.branch_extension_check(True, self.arbor[arborindex][-1], self.arbor[arborindex][-1], self.openpoints, self.s_dist, self.s_ang, self.rel_source_dist, self.arbor)
			
			else:
				#goodextend, nearest = self.math.branch_extension_check(False, self.arbor[arborindex][-1], self.arbor[arborindex][-2], self.openpoints, self.s_dist, self.s_ang, self.source)
				goodextend, nearest = self.math.branch_extension_check(False, self.arbor[arborindex][-1], self.arbor[arborindex][-2], self.openpoints, self.s_dist, self.s_ang, self.rel_source_dist, self.arbor)
			
			if goodextend:
				self.add_to_arbor(nearest) #adds point to end of last key of the arbor
				self.clean_points(nearest) #gets rid of added point from the set of open points
				number_of_points = number_of_points + 1
				stillextending = self.is_acceptable_total_length()
				continue
			
			stillextending = False
		
		return(number_of_points)
	
	def find_branch_point(self):
		goodbranch = False
		for newpoint in self.openpoints: #goes through each open point
			goodbranch, nearest = self.math.choose_first_valid_bifurcation(self.arbor, newpoint, self.source, self.b_ang, self.b_dist, self.rel_source_dist)
			#print(goodbranch,nearest)
			if goodbranch:	
				self.bifurcate(nearest, newpoint)
				self.clean_points(newpoint)
				goodbranch = True
				#print('bifurcated')
				break
		
		return(goodbranch)
	
	def grow(self):
		goodbranch = True
		number_of_points = 0
		self.stamp('grow')
		while len(self.openpoints) > 0 and goodbranch: #grows arbor using prims and find_branch_point methods, till there are no more open points or goodbranch is false
			self.stamp('prims')
			number_of_points = number_of_points + self.prims()
			if not self.is_acceptable_total_length():
				return(number_of_points)
			
			if not self.is_acceptable_number_of_branches():
				return(number_of_points)
			
			self.stamp('prims')
			self.stamp('bifurcate')
			goodbranch = self.find_branch_point()
			self.stamp('bifurcate')
			print(str(round(100.0*float(number_of_points)/float(len(self.allpoints)),2))+'%'+' connected',end="\r", flush=True)
		self.stamp('grow')
		return(number_of_points)


