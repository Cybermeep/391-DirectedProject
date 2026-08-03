// HomiNIDS Loading screen component, plays on refresh and initial load of app

import React from 'react';
import logo from '../assets/logo.png';
import './SplashScreen.css';

const SplashScreen: React.FC = () => (
  <div className="splash-screen">
    <img src={logo} alt="HomiNIDS" className="splash-logo" />
    <div className="splash-dots">
      <span></span>
      <span></span>
      <span></span>
    </div>
  </div>
);

export default SplashScreen;
