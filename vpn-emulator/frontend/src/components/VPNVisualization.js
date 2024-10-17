import React from 'react';

const VPNVisualization = ({ dataFlow }) => {
  return (
    <div>
      <h2>Network Visualization</h2>
      {dataFlow.length > 0 ? (
        dataFlow.map((step, index) => (
          <div key={index}>
            <h4>{step.label}</h4>
            <p>{step.description}</p>
          </div>
        ))
      ) : (
        <p>No VPN running. Please select a protocol and start the VPN.</p>
      )}
    </div>
  );
};

export default VPNVisualization;
