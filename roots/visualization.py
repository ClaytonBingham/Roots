import numpy as np
from mayavi import mlab
import os
from roots.swcToolkit import swcToolkit


class swcVisualizer():
	"""
	
	mfile = 'fileonpath.swc'
	visualizer = swcVisualizer()
	visualizer.mplot_mfile(mfile)
	
	
	"""
	
	def __init__(self):
		self.swcTool = swcToolkit()
	
	def create_cylinders(self,coords,diams,data,num_pts):
		x = []
		y = []
		z = []
		connections = []
		D = []
		offset = 0
		for kk in range(len(coords)):
			# Define points
			C1 = np.array(coords[kk][0])
			C2 = np.array(coords[kk][1])
			
			# Define normal plane
			p = C1-C2
			d = np.dot(p,C1)
			
			# Get normal vectors on plane
			z_idx = np.arange(3)[p==0]
			nz_idx = np.arange(3)[p!=0]
			if len(nz_idx) == 3:
				x1 = 1.
				y1 = 1.
				z1 = (d-(np.dot(p[:2],[x1,y1])))/p[2]
				a = np.array([x1,y1,z1])
			elif len(nz_idx) == 2:
				a = np.zeros(3)
				a[z_idx] = 1.
				a[nz_idx[0]] = 1.
				a[nz_idx[1]] = (d-p[nz_idx[0]])/p[nz_idx[1]]	
			else:
				a = np.zeros(3)
				a[z_idx] = 1.
				a[nz_idx] = d/p[nz_idx]
			a = a-C1
			if len(p[p!=0]) == 3:
				x2 = 1.
				y2 = (a[2]*p[0]/p[2] - a[0]) / (a[1] - a[2]*p[1]/p[2])
				z2 = -(p[1]*y2+p[0])/p[2]
				b = np.array([x2,y2,z2])
			elif len(p[p!=0]) == 2:
				b = np.zeros(3)
				b[z_idx] = 1.
				b[nz_idx[0]] = a[z_idx]/(a[nz_idx[1]]*p[nz_idx[0]]/p[nz_idx[1]] - a[nz_idx[0]])
				b[nz_idx[1]] = -p[nz_idx[0]]*b[nz_idx[0]]/p[nz_idx[1]]
			else:
				b = np.zeros(3)
				b[nz_idx] = 0
				b[z_idx[0]] = 1.
				b[z_idx[1]] = -a[z_idx[0]]/a[z_idx[1]]
			
			# Convert to unit vectors
			a = a/np.linalg.norm(a)
			b = b/np.linalg.norm(b)
			theta_step = np.pi*2/num_pts
			
			# Define set of points at a defined radius around
			# the original points, C1 and C2
			P1 = np.zeros((num_pts,3))
			P2 = np.zeros((num_pts,3))
			r1 = diams[kk][0]
			r2 = diams[kk][1]
			theta = 0
			for ii in range(num_pts):
				for jj in range(3):
					P1[ii][jj] = C1[jj] + r1*np.cos(theta)*a[jj] + r1*np.sin(theta)*b[jj]
					P2[ii][jj] = C2[jj] + r2*np.cos(theta)*a[jj] + r2*np.sin(theta)*b[jj]
				
				theta += theta_step
			
			# Define triangles
			for ii in range(2*num_pts):
				if ii < num_pts:
					connections.append((ii+offset,(ii+1)%num_pts+offset,ii+num_pts+offset))
				else:
					connections.append((ii+offset,(ii+1-num_pts)%num_pts+offset+num_pts,(ii-num_pts+1)%num_pts+offset))
			
			for ii in range(num_pts):
				x.append(P1[ii][0])
				y.append(P1[ii][1])
				z.append(P1[ii][2])
				D.append(data[kk])
			
			for ii in range(num_pts):
				x.append(P2[ii][0])
				y.append(P2[ii][1])
				z.append(P2[ii][2])
				D.append(data[kk])
			
			offset += 2*num_pts
		
		x = np.array(x)
		y = np.array(y)
		z = np.array(z)
		D = np.array(D)
		
		return x, y, z, connections, D
	
	
	def segment_branch(self,branch):
		segments =[]
		for i,seg_end in enumerate(branch[:-1]):
			segments.append([branch[i],branch[i+1]])
		return(segments)
	
	def unzip_sectioned_arbor(self,arbor):
		x = {}
		y = {}
		z = {}
		r = {}
		for branch in arbor.keys():
			x[branch] = []
			y[branch] = []
			z[branch] = []
			r[branch] = []
			for section in arbor[branch]:
				for point in section:
					x[branch].append(point[0])
					y[branch].append(point[1])
					z[branch].append(point[2])
					r[branch].append(point[3])
		
		return(x,y,z,r)
	
	def rgb_to_mlabcolor(self,rgb):
		return((rgb[0]/255.0,rgb[1]/255.0,rgb[2]/255.0))
	
	def mplot_sectioned_arbor_simplified(self,arbor,arbor_labels):
		fig = mlab.figure(bgcolor=(42/255.0,56/255.0,54/255.0),size=(1280,720))
		keys = ['node','paranode1','paranode2','internode','interbouton','bouton']
		values = [self.rgb_to_mlabcolor(item) for item in [(255, 22, 84),(112, 193, 179),(178, 219, 191),(36, 123, 160),((243, 255, 189)),(255, 22, 84)]]
		color_dict = dict(zip(keys,values))
		for branch in arbor.keys():
			if branch not in [0,1]:
				continue
			
			for s,section in enumerate(arbor[branch]):
				mlab.plot3d([sec[0] for sec in section],[sec[1] for sec in section],[sec[2] for sec in section],color=color_dict[arbor_labels[branch][s]],tube_radius=section[-1][-1],tube_sides=6)
		
		mlab.view(azimuth=0,elevation=0)
		
		mlab.show()
	
	
	def plot_electrode(self,arbor,arbor_labels,view=False):
		keys = ['contact','noncontact','activecontact']
		values = [self.rgb_to_mlabcolor(item) for item in [(94, 32, 32),(224, 224, 224),(173,42,42)]]
		color_dict = dict(zip(keys,values))
		electrode_parts = []
		electrode_parts.append(mlab.points3d([arbor[1][0][0][0]],[arbor[1][0][0][1]],[arbor[1][0][0][2]],color=color_dict['noncontact'],scale_factor=arbor[1][0][0][3]*2,mode='sphere',resolution=16))
		for s,section in enumerate(arbor[0]):
			if s in arbor_labels:
				col = color_dict['contact']
				if s == 3:
					col = color_dict['activecontact']
			
			else:
				col = color_dict['noncontact']
			
			electrode_parts.append(mlab.plot3d([sec[0] for sec in section],[sec[1] for sec in section],[sec[2] for sec in section],color=col,tube_radius=section[-1][-1],tube_sides=16))
		
		for part in electrode_parts:
			part.actor.property.backface_culling=True
			part.actor.property.frontface_culling=True
			part.actor.property.shading=True
		if view:
			mlab.show()
	
	
	
	def mplot_sectioned_arbors(self,arbors,colors = [(0.29, 0.58, 0.67),(0.82, 0.35, 0.24)],view=True):
		fig = mlab.figure(bgcolor=(42/255.0,56/255.0,54/255.0),size=(1280,720))
		for arbor in arbors:
			myav_coords = []
			myav_diams = []
			x,y,z,r = self.unzip_sectioned_arbor(arbor)
			coords = []
			diams = []
			for bnum in x:
				tcoords = []
				tdiams = []
				for i,tem in enumerate(x[bnum]):
					tcoords.append([x[bnum][i],y[bnum][i],z[bnum][i]])
					tdiams.append(r[bnum][i])
					tdiams[-1] *= 3.0
				
				coords.extend(self.segment_branch(tcoords))
				diams.extend(self.segment_branch(tdiams))
			
			
			myav_coords.extend(coords)
			myav_diams.extend(diams)
			myav_vs = [20 for i in range(len(myav_coords)-len(coords))]+[2 for j in range(len(coords))]
			num_pts = 20
			tx,ty,tz,tconn,tD = self.create_cylinders(myav_coords,myav_diams,myav_vs,num_pts)
			mlab.triangular_mesh(tx,ty,tz,tconn,scalars=tD,vmin=1,vmax=20)
		
		mlab.view(azimuth=0,elevation=0)
		#	for ii in range(D.shape[1]):
		#		_=mlab.triangular_mesh(x,y,z,connection,scalars = D[:,ii],vmin=Min,vmax=Max)
		#		_=mlab.view(azimuth=0,elevation=0)
		#		_=mlab.savefig('pic%.4d.png' % ii, size=(800,600))
		#	mlab.savefig('pic%.4d.png' % tstep,size=(1200,900))
		
		if view:
			mlab.show()
	
	def view(self):
		mlab.show()
	
	def close(self):
		mlab.close(all=True)
	
	def mplot_sectioned_arbor(self,arbor,colors = [(0.29, 0.58, 0.67),(0.82, 0.35, 0.24)],show=True):
		fig = mlab.figure(bgcolor=(42/255.0,56/255.0,54/255.0),size=(1280,720))
		colorind = 0
		myav_coords = []
		myav_diams = []
		x,y,z,r = self.unzip_sectioned_arbor(arbor)
		coords = []
		diams = []
		for bnum in x:
			tcoords = []
			tdiams = []
			for i,tem in enumerate(x[bnum]):
				tcoords.append([x[bnum][i],y[bnum][i],z[bnum][i]])
				tdiams.append(r[bnum][i])
	#			tdiams[-1] = 0.025
			
			coords.extend(self.segment_branch(tcoords))
			diams.extend(self.segment_branch(tdiams))
		
		
		myav_coords.extend(coords)
		myav_diams.extend(diams)
		myav_vs = [20 for i in range(len(myav_coords)-len(coords))]+[2 for j in range(len(coords))]
		num_pts = 20
		tx,ty,tz,tconn,tD = self.create_cylinders(myav_coords,myav_diams,myav_vs,num_pts)
		mlab.triangular_mesh(tx,ty,tz,tconn,scalars=tD,vmin=1,vmax=20)
		colorind+=1
		mlab.view(azimuth=0,elevation=0)
	#	for ii in range(D.shape[1]):
	#		_=mlab.triangular_mesh(x,y,z,connection,scalars = D[:,ii],vmin=Min,vmax=Max)
	#		_=mlab.view(azimuth=0,elevation=0)
	#		_=mlab.savefig('pic%.4d.png' % ii, size=(800,600))
	#	mlab.savefig('pic%.4d.png' % tstep,size=(1200,900))
		if show:
			mlab.show()
	
	
	def mplot_mfile(self,swcfile,colors = [(0.29, 0.58, 0.67),(0.82, 0.35, 0.24)]):
		colorind = 0
		myav_coords = []
		myav_diams = []
		x,y,z,r = self.swcTool.load_swc(swcfile,asTree=False)
		coords = []
		diams = []
		for bnum in x:
			tcoords = []
			tdiams = []
			for i,tem in enumerate(x[bnum]):
				tcoords.append([x[bnum][i],y[bnum][i],z[bnum][i]])
				tdiams.append(r[bnum][i])
	#			tdiams[-1] = 0.025
			
			coords.extend(self.segment_branch(tcoords))
			diams.extend(self.segment_branch(tdiams))
		
		
		myav_coords.extend(coords)
		myav_diams.extend(diams)
		myav_vs = [20 for i in range(len(myav_coords)-len(coords))]+[2 for j in range(len(coords))]
		num_pts = 6
		tx,ty,tz,tconn,tD = self.create_cylinders(myav_coords,myav_diams,myav_vs,num_pts)
		mlab.triangular_mesh(tx,ty,tz,tconn,scalars=tD,vmin=1,vmax=20,color=colors[colorind])
		colorind+=1
		mlab.view(azimuth=0,elevation=0)
	#	for ii in range(D.shape[1]):
	#		_=mlab.triangular_mesh(x,y,z,connection,scalars = D[:,ii],vmin=Min,vmax=Max)
	#		_=mlab.view(azimuth=0,elevation=0)
	#		_=mlab.savefig('pic%.4d.png' % ii, size=(800,600))
	#	mlab.savefig('pic%.4d.png' % tstep,size=(1200,900))
		mlab.show()







