from neuron import h
import numpy as np

def class BiophysicsManager():
		"""
		This class is used to assign biophysics and discretize NEURON morphologies after they are already created in NEURON python namespace.
		
		Example usage:
		
		```
		bm = BiophysicsManager()
		for section in sectionList:
			bm.assign_biophysics_to_section(sec,type='node')
		
		bm.fixnseg()
		```
		
		This class is dependent upon having the fixnseg.hoc file in root and having nrnivmodl'd an AXNODE.mod and PARAK75.mod in /x86_64 in root.
		
		These items can be found in these places, respectively:
		
		https://senselab.med.yale.edu/ModelDB/ShowModel?model=114685&file=/JohnsonMcIntyre2008/GPe_model/#tabs-2
		
		https://www.neuron.yale.edu/neuron/static/docs/d_lambda/d_lambda.html
		"""

	def __init__(self):
		pass
	
	
	def assign_biophysics_to_section(self,sec,rhoa=0.7e6,type='node'):
		"""
		This class method takes a NEURON section, with an empirically validated rhoa and assigns Johnson & McIntyre (2008) biophysics according to section type (including types: 'node','paranode1','paranode2','internode','unmyelinated')
		
		"""
		if type=='node':
			secref = self.assign_nodal_biophysics(sec,rhoa,0.002)
		
		if type=='paranode1':
			secref = self.assign_paranode1_biophysics(sec,rhoa,0.002)
		
		if type=='paranode2':
			secref = self.assign_paranode2_biophysics(sec,rhoa,0.004)
		
		if type=='internode':
			secref = self.assign_internode_biophysics(sec,rhoa,0.004)
		
		if type=='unmyelinated':
			secref = self.assign_unmyelinated_biophysics(sec,rhoa,0.002)
		
		return(secref)
	
	def fixnseg(self):
		h.xopen("fixnseg.hoc")
		h.geom_nseg()
	
	def assign_unmyelinated_biophysics(self,sec,rhoa,space_p):
		sec.push()
		secref = h.SectionRef()
		sec.nseg = dlambda(sec.diam,sec.L)
		sec.Ra = rhoa/10000
		sec.cm = 1
		h.insert('hh')
		sec.gnabar_hh = 0.35
		sec.insert('extracellular')
		sec.xraxial=(rhoa*.01)/(np.pi*((((sec.diam/2)+space_p)^2)-((sec.diam/2)^2)))
		sec.xg=1e10 
		sec.xc=0
		return(secref)
	
	
	
	def assign_nodal_biophysics(self,sec,rhoa,space_p):
		sec.push()
		secref = h.SectionRef()
		sec.nseg = dlambda(sec.diam,sec.L)
		sec.Ra = rhoa/10000
		sec.cm = 2
		h.insert('axnode75')
		sec.gnabar_axnode75 = 2  
		sec.gnapbar_axnode75 = 0.05 
		sec.gkbar_axnode75 = 0.07
		sec.gl_axnode75 = 0.005
		sec.ek_axnode75 = -85
		sec.ena_axnode75 = 55
		sec.el_axnode75 = -60 
		sec.vshift_axnode75 = 15
		sec.vtraub_axnode75 = -80
		sec.insert('extracellular')
		sec.xraxial=(rhoa*.01)/(np.pi*((((sec.diam/2)+space_p)^2)-((sec.diam/2)^2)))
		sec.xg=1e10 
		sec.xc=0
		return(secref)
	
	
	def assign_paranode1_biophysics(self,sec,rhoa,space_p):
		sec.push()
		secref = h.SectionRef()
		sec.nseg = dlambda(sec.diam,sec.L)
		sec.Ra = rhoa/10000
		sec.cm = 2
		sec.insert('pas')
		sec.g_pas = 0.0001
		sec.e_pas = h.v_init
		sec.insert('extracellular')
		sec.xraxial=(rhoa*.01)/(np.pi*((((sec.diam/2)+space_p)^2)-((sec.diam/2)^2)))
		sec.xg=0.001/2
		sec.xc=0.1/2
		return(secref)
	
	def assign_paranode2_biophysics(self,sec,rhoa,space_p):
		sec.push()
		secref = h.SectionRef()
		sec.nseg = dlambda(sec.diam,sec.L)
		sec.Ra = rhoa/10000
		sec.cm = 2
		sec.insert('parak75')
		sec.gkbar_parak75 = 0.02
		sec.ek_parak75 = -85
		sec.vshift_parak75 = 15
		sec.insert('pas')
		sec.g_pas = 0.0001
		sec.e_pas = h.v_init
		sec.insert('extracellular')
		sec.xraxial=(rhoa*.01)/(np.pi*((((sec.diam/2)+space_p)^2)-((sec.diam/2)^2)))
		sec.xg=0.001/2
		sec.xc=0.1/2
		return(secref)
	
	def assign_internode_biophysics(self,sec,rhoa,space_p):
		sec.push()
		secref = h.SectionRef()
		sec.nseg = dlambda(sec.diam,sec.L)
		sec.Ra = rhoa/10000
		sec.cm = 2
		sec.insert('pas')
		sec.g_pas = 0.0001
		sec.e_pas = h.v_init
		sec.insert('extracellular')
		sec.xraxial=(rhoa*.01)/(np.pi*((((sec.diam/2)+space_p)^2)-((sec.diam/2)^2)))
		sec.xg=0.001/2
		sec.xc=0.1/2
		return(secref)


