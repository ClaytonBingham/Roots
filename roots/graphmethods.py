try:
	import networkx as nx
	import numpy as np

except:
	raise Exception('This class depends upon networkx, numpy. If you are unable to import this package, install it and try again.')


class GraphMethods():
	
	def __init__(self,faces,vertices,source_point,source_index,tri_edge_length_max=175):
		self.graph = self.build_graph(source_point,faces,vertices,tri_edge_length_max)
		source_index = [list(item) for item in list(vertices)].index(list(source_point))
		combos = [[source_index,i+1] for i in range(len(vertices[1:])) if i != source_index]
		self.node_dict,self.paths = self.find_most_likely_paths(source_index,combos)
	
	def euc_dist(self,A,B):
		return(((B[0]-A[0])**2 + (B[1]-A[1])**2 + (B[2]-A[2])**2)**0.5)
	
	def euc_dist_2d(self,A,B):
		return(((B[0]-A[0])**2 + (B[1]-A[1])**2)**0.5)
	
	def distance_filter_pass(self,A,B,threshold_dist):
		if self.euc_dist(A,B) > threshold_dist:
			return(False)
		else:
			return(True)
		
	def build_graph(self,source_point,faces,vertices,tri_edge_length_max):
		G = nx.Graph()
		for pyramid in faces:
			for pair in [[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]]:
				try:
					if self.distance_filter_pass(vertices[pyramid[pair[0]]],vertices[pyramid[pair[1]]],tri_edge_length_max):
						try:
							G.add_edge(pyramid[pair[0]],pyramid[pair[1]],weight = self.euc_dist(vertices[pyramid[pair[0]]],vertices[pyramid[pair[1]]]))
						except:
							print(pyramid[pair[0]],pyramid[pair[1]],'coundt find it in vertices')
					
					###needs to be commented eventually because this is cheating to help arbitrary source points that may not be close to point cloud###
					elif list(source_point) in [list(vertices[pyramid[pair[0]]]),list(vertices[pyramid[pair[1]]])]:
						if self.distance_filter_pass(vertices[pyramid[pair[0]]],vertices[pyramid[pair[1]]],tri_edge_length_max+100):
							try:
								G.add_edge(pyramid[pair[0]],pyramid[pair[1]],weight = self.euc_dist(vertices[pyramid[pair[0]]],vertices[pyramid[pair[1]]]))
							except:
								print(pyramid[pair[0]],pyramid[pair[1]],'coundt find it in vertices')
				except:
					print(pyramid,list(faces).index(pyramid),'couldnt find it in vertices')
		
		return(G)
	
	def list_sort_by_size(self,LOLs):
		return(list(reversed(sorted(LOLs,key=len))))
	
	def less_than_count(self,incomplete_paths,p):
		return(p-len([l for l in incomplete_paths if l<p]))
	
	def find_longest_inclusive_paths(self,paths):
		paths = self.list_sort_by_size(paths)
		node_dict = {}
		for p,path in enumerate(paths):
			for node in path:
				if node not in node_dict.keys():
					node_dict[node] = p
		
		complete_paths = node_dict.values()
		incomplete_paths = [p for p,path in enumerate(paths) if p not in complete_paths]
		return(dict(zip(node_dict.values(),[self.less_than_count(incomplete_paths,p) for p in complete_paths])),[path for p,path in enumerate(paths) if p in complete_paths])
	
	def find_most_likely_paths(self,source_index,combos):
		paths = []
		for c,combo in enumerate(combos):
			try:
				paths.append(nx.dijkstra_path(self.graph,source_index,combo[1]))
			except:
				pass
		
		return(self.find_longest_inclusive_paths(paths))

