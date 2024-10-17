import React, { useState } from 'react';

const VPNConfig = ({ onStartVPN }) => {
  const [protocol, setProtocol] = useState('PPTP');

  const handleProtocolChange = (e) => {
    setProtocol(e.target.value);
  };

  const handleStart = () => {
    onStartVPN(protocol);
  };

  return (
    <div>
      <h2>Select VPN Protocol</h2>
      <select value={protocol} onChange={handleProtocolChange}>
        <option value="PPTP">PPTP</option>
        <option value="L2TP">L2TP</option>
        <option value="IPSec">IPSec</option>
      </select>
      <button onClick={handleStart}>Start VPN</button>
    </div>
  );
};

export default VPNConfig;
