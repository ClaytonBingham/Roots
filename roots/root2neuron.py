import os

class Root2Hoc():
	"""
	This class is designed to take an existing morphology and write the topology and morphology to a .hoc file that can be used to run NEURON simulations using existing models.
	
	```
	hoc_writer = Root2Hoc()
	hoc_writer.primarytest()
	arbor = hoc_writer.test_arbor()
	print(arbor)
	hoc_writer.arbor_to_nrn(arbor)
	```
	
	"""
	
	def __init__(self):
		pass
	
	def strip_diameters_for_comparison(self,li):
		if any(isinstance(i, list) for i in li):
			newli = []
			if any(isinstance(i, list) for i in li[0]):
				for section in li:
					newli.append([point[:3] for point in section])
				
				return(newli)
			
			else:
				return([point[:3] for point in li])
		
		else:
			return(li[:3])
	
	def lookup_section_by_point(self,arbor,point,home_branch):
		sec_index = 0
		for branch in arbor.keys():
			if branch == home_branch:
				continue
			for section in arbor[branch]:
				if self.strip_diameters_for_comparison(point) in self.strip_diameters_for_comparison(section):
					return(sec_index,self.strip_diameters_for_comparison(section).index(self.strip_diameters_for_comparison(point))/float(len(section)-1))
				
				else:
					sec_index+=1
		
		return(None,None)
	
	def count_sections(self,arbor):
		sec_count = 0
		for branch in arbor.keys():
			for section in arbor[branch]:
				sec_count+=1
		
		return(sec_count)
	
	def build_section_indices(self,arbor):
		"""
		
		builds a dictionary of indices that match the arbor sections and is used to label sections while building the connections/topology
		
		"""
		
		section_indices = {}
		sec_ind = 0
		for branch in arbor.keys():
			section_indices[branch] = []
			for section in arbor[branch]:
				section_indices[branch].append(sec_ind)
				sec_ind+=1
		
		return(section_indices)
	
	def build_topology_list(self,arbor):
		section_indices = self.build_section_indices(arbor)
		connections = []
		for branch in arbor.keys():
			if branch != 0:
				ind,position = self.lookup_section_by_point(arbor,arbor[branch][0][0],branch)
				if ind==None:
					raise(ValueError)
				
				connections.append(([ind,int(position)],[section_indices[branch][0],0]))
			
			for section in arbor[branch][:-1]:
				connections.append(([section_indices[branch][arbor[branch].index(section)],1],[section_indices[branch][arbor[branch].index(section)]+1,0]))
		
		return(connections)
	
	def arbor_to_nrn_topology(self,arbor):
		topo_list = self.build_topology_list(arbor)
		number_of_sections = self.count_sections(arbor)
		topo_func = '//Building axon topology\n\n'
		topo_func+= f'create sectionList[{number_of_sections}]'
		
		for connection in topo_list:
			topo_func+=f'\nconnect sectionList[{connection[1][0]}]({connection[1][1]}), sectionList[{connection[0][0]}]({connection[0][1]})'
		
		return(topo_func+'\n')
	
	def nrn_build_section(self,section_index,section_points):
		nrn_command=f'sectionList[{section_index}]'+'{\n'
		for point in section_points:
			if len(point) < 4:
				nrn_command+=f'\tpt3dadd({point[0]},{point[1]},{point[2]},1)\n'
			else:
				nrn_command+=f'\tpt3dadd({point[0]},{point[1]},{point[2]},{point[3]})\n'
		
		
		return(nrn_command+'}\n')
	
	def arbor_to_nrn_morphology(self,arbor):
		"""
		//Set up axon geometry
		
		
		//MAIN AXON
		node[0]{
		    pt3dadd(-10338,2909.5,-316.24,nodeD)
		    pt3dadd(-10338.3947,2910.3684,-315.94,nodeD)
		}
		"""
		morpho_func='\n//Set up axon geometry\n\n//MAIN AXON\n\n'
		section_index = 0
		for branch in arbor.keys():
			for section in arbor[branch]:
				morpho_func+=self.nrn_build_section(section_index,section)
				section_index+=1
		
		
		
		return(morpho_func)
	
	
	def arbor_to_nrn(self,arbor,labels,target=os.getcwd()+'/testmorphology.hoc'):
		topology_function = self.arbor_to_nrn_topology(arbor)
		morphology_function = self.arbor_to_nrn_morphology(arbor)
		with open(target,'w') as f:
			f.write(topology_function+'\n\n'+morphology_function+'\n\n')
		
		return(topology_function+'\n\n'+morphology_function+'\n\n')
	
	def test_arbor(self):
		arbor = {}
		arbor[0] = [[[0,0,0,1],[1,0,0,1],[2,0,0,1]],[[2,0,0,1],[3,0,0,1],[4,0,0,1]],[[4,0,0,1],[5,0,0,1],[6,0,0,1]]]
		arbor[1] = [[[2,0,0,1],[2,1,0,1],[2,2,0,1]],[[2,2,0,1],[2,3,0,1],[2,4,0,1]]]
		arbor[2] = [[[4,0,0,1],[4,0,1,1],[4,0,2,1]],[[4,0,2,1],[4,0,3,1],[4,0,4,1]]]
		
		
		return(arbor)
	
	def primarytest(self):
		arbor = self.test_arbor()
		if self.lookup_section_by_point(arbor,[3,0,0,1])[0] == 1:
			print('lookup_section_by_point() --passed')
		
		else:
			print('lookup_section_by_point() --failed')
		
		if self.count_sections(arbor) == 7:
			print('count_sections() --passed')
		
		else:
			print('count_sections() --failed')
		
		if self.build_topology_list(arbor) == [([0, 1], [1, 0]), ([1, 1], [2, 0]), ([0, 1], [3, 0]), ([3, 1], [4, 0]), ([1, 1], [5, 0]), ([5, 1], [6, 0])]:
			print('build_section_list() --passed\nbuild_section_indices() --passed')
		
		else:
			print('build_section_list() --failed\nbuild_section_indices() --failed')
		
		if self.arbor_to_nrn_topology(arbor) == '//Building axon topology\n\ncreate sectionList[7]\nconnect sectionList[0](1), sectionList[1](0)\nconnect sectionList[1](1), sectionList[2](0)\nconnect sectionList[0](1), sectionList[3](0)\nconnect sectionList[3](1), sectionList[4](0)\nconnect sectionList[1](1), sectionList[5](0)\nconnect sectionList[5](1), sectionList[6](0)\n':
			print('arbor_to_nrn_topology() --passed')
		
		else:
			print('arbor_to_nrn_topology() --failed')
		
		if self.nrn_build_section(0,arbor[0][0]) =='sectionList[0]{\n\tpt3dadd(0,0,0,1)\n\tpt3dadd(1,0,0,1)\n\tpt3dadd(2,0,0,1)\n}\n':
			print('nrn_build_section() --passed')
		
		else:
			print('nrn_build_section() --failed')
		
		if self.arbor_to_nrn_morphology(arbor) =='\n//Set up axon geometry\n\n//MAIN AXON\n\nsectionList[0]{\n\tpt3dadd(0,0,0,1)\n\tpt3dadd(1,0,0,1)\n\tpt3dadd(2,0,0,1)\n}\nsectionList[1]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(3,0,0,1)\n\tpt3dadd(4,0,0,1)\n}\nsectionList[2]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(5,0,0,1)\n\tpt3dadd(6,0,0,1)\n}\nsectionList[3]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(2,1,0,1)\n\tpt3dadd(2,2,0,1)\n}\nsectionList[4]{\n\tpt3dadd(2,2,0,1)\n\tpt3dadd(2,3,0,1)\n\tpt3dadd(2,4,0,1)\n}\nsectionList[5]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(4,0,1,1)\n\tpt3dadd(4,0,2,1)\n}\nsectionList[6]{\n\tpt3dadd(4,0,2,1)\n\tpt3dadd(4,0,3,1)\n\tpt3dadd(4,0,4,1)\n}\n':
			print('arbor_to_nrn_morphology() --passed')
		
		else:
			print('arbor_to_nrn_morphology() --failed')
		
		if self.arbor_to_nrn(arbor) == '//Building axon topology\n\ncreate sectionList[7]\nconnect sectionList[0](1), sectionList[1](0)\nconnect sectionList[1](1), sectionList[2](0)\nconnect sectionList[0](1), sectionList[3](0)\nconnect sectionList[3](1), sectionList[4](0)\nconnect sectionList[1](1), sectionList[5](0)\nconnect sectionList[5](1), sectionList[6](0)\n\n\n\n//Set up axon geometry\n\n//MAIN AXON\n\nsectionList[0]{\n\tpt3dadd(0,0,0,1)\n\tpt3dadd(1,0,0,1)\n\tpt3dadd(2,0,0,1)\n}\nsectionList[1]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(3,0,0,1)\n\tpt3dadd(4,0,0,1)\n}\nsectionList[2]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(5,0,0,1)\n\tpt3dadd(6,0,0,1)\n}\nsectionList[3]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(2,1,0,1)\n\tpt3dadd(2,2,0,1)\n}\nsectionList[4]{\n\tpt3dadd(2,2,0,1)\n\tpt3dadd(2,3,0,1)\n\tpt3dadd(2,4,0,1)\n}\nsectionList[5]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(4,0,1,1)\n\tpt3dadd(4,0,2,1)\n}\nsectionList[6]{\n\tpt3dadd(4,0,2,1)\n\tpt3dadd(4,0,3,1)\n\tpt3dadd(4,0,4,1)\n}\n\n\n':
			print('arbor_to_nrn() --passed')
		
		else:
			print('arbor_to_nrn() --failed')




class Root2Py():
	"""
	This class is designed to take an existing morphology and write the topology and morphology to a .py file that can be used to run NEURON simulations using existing models.
	
	```
	nrn_writer = Root2Py()
	nrn_writer.primarytest()
	arbor = nrn_writer.test_arbor()
	print(arbor)
	nrn.arbor_to_nrn(arbor)
	```
	
	"""
	
	def __init__(self):
		pass
	
	def strip_diameters_for_comparison(self,li):
		if any(isinstance(i, list) for i in li):
			newli = []
			if any(isinstance(i, list) for i in li[0]):
				for section in li:
					newli.append([point[:3] for point in section])
				return(newli)
			
			else:
				return([point[:3] for point in li])
		
		else:
			return(li[:3])
	
	def lookup_section_by_point(self,arbor,point,home_branch):
		sec_index = 0
		for branch in arbor.keys():
			if branch == home_branch:
				continue
			for section in arbor[branch]:
				if self.strip_diameters_for_comparison(point) in self.strip_diameters_for_comparison(section):
					return(sec_index,self.strip_diameters_for_comparison(section).index(self.strip_diameters_for_comparison(point))/float(len(section)-1))
				
				else:
					sec_index+=1
		
		return(None,None)
	
	def count_sections(self,arbor):
		sec_count = 0
		for branch in arbor.keys():
			for section in arbor[branch]:
				sec_count+=1
		
		return(sec_count)
	
	def build_section_indices(self,arbor):
		"""
		
		builds a dictionary of indices that match the arbor sections and is used to label sections while building the connections/topology
		
		"""
		
		section_indices = {}
		sec_ind = 0
		for branch in arbor.keys():
			section_indices[branch] = []
			for section in arbor[branch]:
				section_indices[branch].append(sec_ind)
				sec_ind+=1
		
		return(section_indices)
	
	def build_topology_list(self,arbor):
		section_indices = self.build_section_indices(arbor)
		connections = []
		for branch in arbor.keys():
			if branch != 0:
				ind,position = self.lookup_section_by_point(arbor,arbor[branch][0][0],branch)
				if ind==None:
					raise(ValueError)
				
				connections.append(([ind,int(position)],[section_indices[branch][0],0]))
			
			for section in arbor[branch][:-1]:
				connections.append(([section_indices[branch][arbor[branch].index(section)],1],[section_indices[branch][arbor[branch].index(section)]+1,0]))
		
		return(connections)
	
	def arbor_to_nrn_topology(self,arbor):
		topo_list = self.build_topology_list(arbor)
		number_of_sections = self.count_sections(arbor)
		topo_func = '#Building axon topology\n\nfrom neuron import h\n\n'
		topo_func+= f'sectionList = [h.Section() for i in range({number_of_sections})]'
		
		for connection in topo_list:
			topo_func+=f'\nsectionList[{connection[1][0]}].connect(sectionList[{connection[0][0]}]({connection[0][1]}),{connection[1][1]})'
		
		return(topo_func+'\n')
	
	def nrn_build_section(self,section_index,section_points):
		nrn_command='\n\n'
		for point in section_points:
			if len(point) < 4:
				nrn_command+=f'h.pt3dadd({point[0]},{point[1]},{point[2]},1,sec=sectionList[{section_index}])\n'
			else:
				nrn_command+=f'h.pt3dadd({point[0]},{point[1]},{point[2]},{point[3]},sec=sectionList[{section_index}])\n'
		
		
		return(nrn_command)
	
	def arbor_to_nrn_morphology(self,arbor):
		"""
		#Set up axon geometry
		
		
		#MAIN AXON
		node[0] = h.Section()
		h.pt3dadd(-10338,2909.5,-316.24,nodeD,sec=node[0])
		h.pt3dadd(-10338.3947,2910.3684,-315.94,nodeD,sec=node[0])
		
		"""
		nrn_morpho_func='\n#Set up axon geometry\n\n#MAIN AXON\n\n'
		section_index = 0
		for branch in arbor.keys():
			for section in arbor[branch]:
				nrn_morpho_func+=self.nrn_build_section(section_index,section)
				section_index+=1
		
		
		
		return(nrn_morpho_func)
	
	
	def arbor_to_nrn(self,arbor,labels,target=os.getcwd()+'/testmorphology.py'):
		topology_function = self.arbor_to_nrn_topology(arbor)
		morphology_function = self.arbor_to_nrn_morphology(arbor)
		with open(target,'w') as f:
			f.write(topology_function+'\n\n'+morphology_function+'\n\n')
		
		return(topology_function+'\n\n'+morphology_function+'\n\n')
	
	def test_arbor(self):
		arbor = {}
		arbor[0] = [[[0,0,0,1],[1,0,0,1],[2,0,0,1]],[[2,0,0,1],[3,0,0,1],[4,0,0,1]],[[4,0,0,1],[5,0,0,1],[6,0,0,1]]]
		arbor[1] = [[[2,0,0,1],[2,1,0,1],[2,2,0,1]],[[2,2,0,1],[2,3,0,1],[2,4,0,1]]]
		arbor[2] = [[[4,0,0,1],[4,0,1,1],[4,0,2,1]],[[4,0,2,1],[4,0,3,1],[4,0,4,1]]]
		
		
		return(arbor)
	
	def primarytest(self):
		arbor = self.test_arbor()
		if self.lookup_section_by_point(arbor,[3,0,0,1])[0] == 1:
			print('lookup_section_by_point() --passed')
		
		else:
			print('lookup_section_by_point() --failed')
		
		if self.count_sections(arbor) == 7:
			print('count_sections() --passed')
		
		else:
			print('count_sections() --failed')
		
		if self.build_topology_list(arbor) == [([0, 1], [1, 0]), ([1, 1], [2, 0]), ([0, 1], [3, 0]), ([3, 1], [4, 0]), ([1, 1], [5, 0]), ([5, 1], [6, 0])]:
			print('build_section_list() --passed\nbuild_section_indices() --passed')
		
		else:
			print('build_section_list() --failed\nbuild_section_indices() --failed')
		
		if self.arbor_to_nrn_topology(arbor) == '//Building axon topology\n\ncreate sectionList[7]\nconnect sectionList[0](1), sectionList[1](0)\nconnect sectionList[1](1), sectionList[2](0)\nconnect sectionList[0](1), sectionList[3](0)\nconnect sectionList[3](1), sectionList[4](0)\nconnect sectionList[1](1), sectionList[5](0)\nconnect sectionList[5](1), sectionList[6](0)\n':
			print('arbor_to_nrn_topology() --passed')
		
		else:
			print('arbor_to_nrn_topology() --failed')
		
		if self.nrn_build_section(0,arbor[0][0]) =='sectionList[0]{\n\tpt3dadd(0,0,0,1)\n\tpt3dadd(1,0,0,1)\n\tpt3dadd(2,0,0,1)\n}\n':
			print('nrn_build_section() --passed')
		
		else:
			print('nrn_build_section() --failed')
		
		if self.arbor_to_nrn_morphology(arbor) =='\n//Set up axon geometry\n\n//MAIN AXON\n\nsectionList[0]{\n\tpt3dadd(0,0,0,1)\n\tpt3dadd(1,0,0,1)\n\tpt3dadd(2,0,0,1)\n}\nsectionList[1]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(3,0,0,1)\n\tpt3dadd(4,0,0,1)\n}\nsectionList[2]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(5,0,0,1)\n\tpt3dadd(6,0,0,1)\n}\nsectionList[3]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(2,1,0,1)\n\tpt3dadd(2,2,0,1)\n}\nsectionList[4]{\n\tpt3dadd(2,2,0,1)\n\tpt3dadd(2,3,0,1)\n\tpt3dadd(2,4,0,1)\n}\nsectionList[5]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(4,0,1,1)\n\tpt3dadd(4,0,2,1)\n}\nsectionList[6]{\n\tpt3dadd(4,0,2,1)\n\tpt3dadd(4,0,3,1)\n\tpt3dadd(4,0,4,1)\n}\n':
			print('arbor_to_nrn_morphology() --passed')
		
		else:
			print('arbor_to_nrn_morphology() --failed')
		
		if self.arbor_to_nrn(arbor) == '//Building axon topology\n\ncreate sectionList[7]\nconnect sectionList[0](1), sectionList[1](0)\nconnect sectionList[1](1), sectionList[2](0)\nconnect sectionList[0](1), sectionList[3](0)\nconnect sectionList[3](1), sectionList[4](0)\nconnect sectionList[1](1), sectionList[5](0)\nconnect sectionList[5](1), sectionList[6](0)\n\n\n\n//Set up axon geometry\n\n//MAIN AXON\n\nsectionList[0]{\n\tpt3dadd(0,0,0,1)\n\tpt3dadd(1,0,0,1)\n\tpt3dadd(2,0,0,1)\n}\nsectionList[1]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(3,0,0,1)\n\tpt3dadd(4,0,0,1)\n}\nsectionList[2]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(5,0,0,1)\n\tpt3dadd(6,0,0,1)\n}\nsectionList[3]{\n\tpt3dadd(2,0,0,1)\n\tpt3dadd(2,1,0,1)\n\tpt3dadd(2,2,0,1)\n}\nsectionList[4]{\n\tpt3dadd(2,2,0,1)\n\tpt3dadd(2,3,0,1)\n\tpt3dadd(2,4,0,1)\n}\nsectionList[5]{\n\tpt3dadd(4,0,0,1)\n\tpt3dadd(4,0,1,1)\n\tpt3dadd(4,0,2,1)\n}\nsectionList[6]{\n\tpt3dadd(4,0,2,1)\n\tpt3dadd(4,0,3,1)\n\tpt3dadd(4,0,4,1)\n}\n\n\n':
			print('arbor_to_nrn() --passed')
		
		else:
			print('arbor_to_nrn() --failed')

