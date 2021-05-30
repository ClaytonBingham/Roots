import numpy as np

class LinearAddMicrostructures():
	def __init__(self,arbor,myelinlist=[],boutonlist=[],myelindimensions=dict(zip(['node','paranode1','paranode2','internode','paranode2','paranode1'],[1,3,46,234,46,3])),boutondimensions=dict(zip(['bouton','interbouton'],[5,28]))):
		self.arbor = deepcopy(arbor)
		self.labels = dict(zip(self.arbor.keys(),[[] for key in self.arbor.keys()]))
		for m in myelinlist:
			self.arbor[m],self.labels[m] = self.iterate_microstructures_on_branch(self.arbor[m],list(myelindimensions.values()),list(myelindimensions.keys()))
		
		for b in boutonlist:
			self.arbor[b],self.labels[b] = self.iterate_microstructures_on_branch(self.arbor[b],list(boutondimensions.values()),list(boutondimensions.keys()))
	
		self.get_arbor_lengths()
	
	def check_return_results(self):
		if len(self.arbor.values()) != len(self.labels.values()) != len(self.lengths.values()):
			print("Arbor, Labels, and Lengths aren't lined up!...double check what you are getting")
		return(self.arbor,self.labels,self.lengths)
	
	def get_vector_and_magnitude(self,a,b):
		b = np.array(b)
		a = np.array(a)
		vec = b-a
		return(vec,np.linalg.norm(vec))

	def try_get_section_from_vec(self,a,b,seclen):
		vec,mag = self.get_vector_and_magnitude(a,b)
		if mag >= seclen:
			return(list(np.array(a)+vec*(seclen/mag)),seclen)
		if mag < seclen:
			return(b,mag)

	def eucdist3d(self,point1,point2):
		"""
		
		euclidean distance between point1 and point2 - [x,y,z]
		
		"""
		
		return(((point2[0]-point1[0])**2 + (point2[1]-point1[1])**2 + (point2[2]-point1[2])**2)**0.5)
	
	def get_arbor_lengths(self):
		self.lengths = {}
		for branch in self.arbor.keys():
			self.lengths[branch] = []
			for item in self.arbor[branch]:
				self.lengths[branch].append(0)
				for p,point in enumerate(item[:-1]):
					self.lengths[branch][-1]+=self.eucdist3d(point,item[p+1])
	
	def try_get_section_from_branch(self,branch,seclen):
		down_branch = deepcopy(branch)
		newsection = [down_branch.pop(0)]
		while seclen > 0 and len(down_branch) > 0:
			end,secless = self.try_get_section_from_vec(newsection[-1],down_branch[0],seclen)
			if down_branch[0] == end:
				down_branch.pop(0)
			
			newsection.append(end)
			seclen-=secless
		
		down_branch = [end]+down_branch
		return(newsection,down_branch)

	def reserve_last_section(self,down_branch,seclen):
		localbranch = list(reversed(down_branch))
		lastsection,localbranch = self.try_get_section_from_branch(localbranch,seclen)
		return(list(reversed(lastsection)),list(reversed(localbranch)))

	def iterate_microstructures_on_branch(self,branch,microstructure_dimensions,microstructures_labels):
		dimind = 0
		newbranch = []
		newlabels = []
		localbranch = deepcopy(branch)
		lastsection,remaining = self.reserve_last_section(localbranch,microstructure_dimensions[dimind])
		lastlabel = microstructures_labels[dimind]
		while len(remaining) >1:
			newsection,remaining = self.try_get_section_from_branch(remaining,microstructure_dimensions[dimind])
			newbranch.append(newsection)
			newlabels.append(microstructures_labels[dimind])
			dimind+=1
			if dimind == len(microstructure_dimensions):
				dimind = 0
			
			print(remaining)
		
		newbranch.append(lastsection)
		newlabels.append(lastlabel)
		return(newbranch,newlabels)




if __name__ == "__main__":
	from copy import deepcopy
	arbor = dict(zip([0],[[(i*1000,0,0) for i in range(11)]]))
	m = LinearAddMicrostructures(arbor,[0],[])
	newarbor,labels,lengths = m.check_return_results()

