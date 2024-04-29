import React from 'react'
import Home from '../pages/Home'
import Services from '../pages/Services'
import Login from '../pages/Login'
import Signup from '../pages/Signup'
import Contact from '../pages/Contact'
import Doctors from '../pages/Doctors/Doctors'
import VirtualAssistent from '../Pages/VirtualAssistent'
import Room from '../Pages/Room'
import DoctorDetails from '../pages/Doctors/DoctorDetails'
import Dashboard from '../Dashboard/doctor-account/Dashboard'
import MyAccount from '../Dashboard/user-account/MyAccount'
import ProtectedRoute from './ProtectedRoute';
import CheckoutSuccess from '../pages/CheckoutSuccess'


import {Routes , Route} from 'react-router-dom'



export default function Routers() {
  return (
    <Routes>
      <Route path='/' element={<Home/>} />
      <Route path='/home' element={<Home/>} />
      <Route path='/doctors' element={<Doctors/>} />
      <Route path='/virassistent' element={<VirtualAssistent/>} />
      <Route path="/room/:roomId" element={<Room />} />
      <Route path='/doctors/:id' element={<DoctorDetails/>} />
      <Route path='/login' element={<Login/>} />
      <Route path='/register' element={<Signup/>} />
      <Route path='/contact' element={<Contact/>} />
      <Route path='/services' element={<Services/>} />
      <Route path='/checkout-success' element={<CheckoutSuccess/>} />
      <Route path='/*' element={<Home/>}/>
      <Route path="/users/profile/me" element={<ProtectedRoute allowedRoles={["patient"]}><MyAccount /></ProtectedRoute>} />
      <Route path="/doctors/profile/me" element={<ProtectedRoute allowedRoles={["doctor"]}><Dashboard /></ProtectedRoute>} />

    </Routes>
  )
}

