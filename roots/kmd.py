try:
	from mayavi import mlab
	import numpy as np
except:
	print('Some elements of this package depend on mayavi2,numpy. Install mayavi to ensure mlab can be successfully imported and try again.')

try:
	import matplotlib.pyplot as plt
	from mpl_toolkits.mplot3d import Axes3D
except:
	print('Some elements of this package depend upon matplotlib and mpl_toolkits.mplot3d. If you are unable to import these, install them and try again.')

class KMDD():
	def __init__(self,source_point,points_outer,cluster_reduce=0.15,tri_edge_length_max=175):
		self.source_point = source_point
		self.points_outer = points_outer
		self.cluster_reduce = cluster_reduce
		self.tri_edge_length_max = tri_edge_length_max
		self.vertices,self.faces = self.return_meshed_point_cloud(source_point,points_outer,cluster_reduce)
#		self.plot_clusters_and_points(self.vertices,points_outer)
		self.mayavi_plot_delaunay_tri(source_point,tri_edge_length_max)
	
	def plot_clusters_and_points(self,clusters,points):
		fig = plt.figure()
		ax = Axes3D(fig)
		ax.scatter([point[0] for point in clusters],[point[1] for point in clusters],[point[2] for point in clusters],'.r',label='All Points',s=3.5)
		ax.scatter([point[0] for point in points[::5]],[point[1] for point in points[::5]],[point[2] for point in points[::5]],'.k',label='All Points',s=2)
		plt.show()

	def euc_dist(self,A,B):
		return(((B[0]-A[0])**2 + (B[1]-A[1])**2 + (B[2]-A[2])**2)**0.5)

	def euc_dist_2d(self,A,B):
		return(((B[0]-A[0])**2 + (B[1]-A[1])**2)**0.5)

	def distance_filter_pass(self,A,B,threshold_dist):
		if self.euc_dist(A,B) > threshold_dist:
			return(False)
		else:
			return(True)

	def return_meshed_point_cloud(self,sourcepoint, points,simplify=0.1):
		#from sklearn.cluster import KMeans as kmeans
		from sklearn.cluster import MiniBatchKMeans as mbkmeans
		from scipy.spatial import Delaunay as delaunay
		nclusters = int(len(points)*simplify)
		#km = kmeans(n_clusters=nclusters, init='k-means++', n_init=10, max_iter=300, tol=0.0001, precompute_distances='auto', verbose=0, random_state=None, copy_x=True, n_jobs=1, algorithm='auto').fit(points) 
		km = mbkmeans(n_clusters=nclusters, init='k-means++', n_init=10, max_iter=300, tol=0.001, verbose=0, random_state=None, init_size=3*nclusters).fit(points) 
		self.clusters = km.cluster_centers_
		clusters = [list(item) for item in list(km.cluster_centers_)]
		if list(sourcepoint) in clusters:
			print('sourcepoint already in clusters')
		else:
			clusters=[list(sourcepoint)]+clusters
		
		print('got '+str(len(clusters))+' clusters')
		tri_volume = delaunay(np.array(clusters), furthest_site=False, incremental=False, qhull_options=None)
		return(tri_volume.points,tri_volume.simplices)
	
	def mayavi_plot_delaunay_tri(self,source_point,dist_threshold):
		src = mlab.pipeline.scalar_scatter(np.array([pt[0] for pt in self.vertices]), np.array([pt[1] for pt in self.vertices]), np.array([pt[2] for pt in self.vertices]), np.array([1 for pt in self.vertices]))
		connections = []
		for pyramid in self.faces:
			for pair in [[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]]:
				if self.distance_filter_pass(self.vertices[pyramid[pair[0]]],self.vertices[pyramid[pair[1]]],dist_threshold):
					connections.append(np.array([pyramid[pair[0]],pyramid[pair[1]]]))
					continue
				
				if list(source_point) in [list(self.vertices[pyramid[pair[0]]]),list(self.vertices[pyramid[pair[1]]])]:
					if self.distance_filter_pass(self.vertices[pyramid[pair[0]]],self.vertices[pyramid[pair[1]]],dist_threshold+100):
						connections.append(np.array([pyramid[pair[0]],pyramid[pair[1]]]))
		
		
		connections = np.vstack(tuple(connections))
		src.mlab_source.dataset.lines = connections
		src.update()
		lines = mlab.pipeline.stripper(src)
		mlab.pipeline.surface(lines, colormap='Accent', line_width=1, opacity=.4)
		mlab.show()
