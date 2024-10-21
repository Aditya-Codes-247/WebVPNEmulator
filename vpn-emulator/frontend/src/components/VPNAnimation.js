import React from 'react';
import { motion } from 'framer-motion';

const VPNAnimation = ({ protocol, dataFlow }) => {
  const containerVariants = {
    hidden: { opacity: 0, y: -50 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { type: 'spring', mass: 0.8, damping: 10, staggerChildren: 0.2 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, scale: 0.8 },
    visible: { opacity: 1, scale: 1 }
  };

  return (
    <motion.div
      className="vpn-animation"
      initial="hidden"
      animate="visible"
      variants={containerVariants}
    >
      <h3>VPN Protocol: {protocol}</h3>
      <ul>
        {dataFlow.map((step, index) => (
          <motion.li key={index} className="vpn-step" variants={itemVariants}>
            <strong>{step.label}:</strong> {step.description}
          </motion.li>
        ))}
      </ul>
    </motion.div>
  );
};

export default VPNAnimation;
