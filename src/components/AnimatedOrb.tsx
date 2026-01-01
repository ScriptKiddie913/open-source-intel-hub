// ============================================================================
// AnimatedOrb.tsx
// ANIMATED BLUE ORB WITH DISINTEGRATION EFFECT
// ============================================================================
// ✔ Smooth particle disintegration and reintegration
// ✔ Follows cursor direction when integrated
// ✔ Canvas-based particle system
// ============================================================================

'use client';

import React, { useRef, useEffect, useState, useCallback } from 'react';
import { cn } from '@/lib/utils';

/* ============================================================================
   TYPES
============================================================================ */

interface Particle {
  x: number;
  y: number;
  originX: number;
  originY: number;
  size: number;
  color: string;
  alpha: number;
  velocity: { x: number; y: number };
  angle: number;
  speed: number;
  targetX: number;
  targetY: number;
  delay: number;
}

interface AnimatedOrbProps {
  className?: string;
  size?: number;
  particleCount?: number;
  cycleSpeed?: number;
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function AnimatedOrb({
  className,
  size = 200,
  particleCount = 800,
  cycleSpeed = 0.0008,
}: AnimatedOrbProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const animationRef = useRef<number | null>(null);
  const phaseRef = useRef<'integrated' | 'disintegrating' | 'disintegrated' | 'reintegrating'>('integrated');
  const phaseProgressRef = useRef(0);
  const mouseRef = useRef({ x: 0, y: 0 });
  const centerRef = useRef({ x: 0, y: 0 });
  
  // Initialize particles
  const initParticles = useCallback(() => {
    const particles: Particle[] = [];
    const canvas = canvasRef.current;
    if (!canvas) return particles;
    
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    centerRef.current = { x: centerX, y: centerY };
    
    const radius = size / 2;
    
    for (let i = 0; i < particleCount; i++) {
      // Generate points within sphere
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = radius * Math.cbrt(Math.random()); // Uniform distribution in sphere
      
      const x = centerX + r * Math.sin(phi) * Math.cos(theta);
      const y = centerY + r * Math.sin(phi) * Math.sin(theta);
      
      // Vary blue shades
      const blue = 150 + Math.floor(Math.random() * 105);
      const green = 80 + Math.floor(Math.random() * 80);
      
      // Random explosion direction
      const angle = Math.random() * Math.PI * 2;
      const speed = 0.5 + Math.random() * 2;
      
      particles.push({
        x,
        y,
        originX: x,
        originY: y,
        size: 1 + Math.random() * 2.5,
        color: `rgb(${30 + Math.floor(Math.random() * 50)}, ${green}, ${blue})`,
        alpha: 0.4 + Math.random() * 0.6,
        velocity: { x: 0, y: 0 },
        angle,
        speed,
        targetX: x + Math.cos(angle) * (100 + Math.random() * 150),
        targetY: y + Math.sin(angle) * (100 + Math.random() * 150),
        delay: Math.random() * 0.3,
      });
    }
    
    return particles;
  }, [size, particleCount]);
  
  // Handle mouse movement
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY };
    };
    
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);
  
  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Set canvas size
    const resizeCanvas = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      particlesRef.current = initParticles();
    };
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    let lastTime = 0;
    const cycleDuration = 20000; // 8 seconds per full cycle
    
    const animate = (time: number) => {
      const deltaTime = time - lastTime;
      lastTime = time;
      
      // Update phase progress
      phaseProgressRef.current += cycleSpeed * deltaTime;
      
      // Determine current phase
      const cycleProgress = phaseProgressRef.current % 1;
      
      if (cycleProgress < 0.35) {
        phaseRef.current = 'integrated';
      } else if (cycleProgress < 0.5) {
        phaseRef.current = 'disintegrating';
      } else if (cycleProgress < 0.65) {
        phaseRef.current = 'disintegrated';
      } else {
        phaseRef.current = 'reintegrating';
      }
      
      // Clear canvas
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Calculate eye direction (only when integrated)
      let eyeOffsetX = 0;
      let eyeOffsetY = 0;
      
      if (phaseRef.current === 'integrated') {
        const rect = canvas.getBoundingClientRect();
        const canvasCenterX = rect.left + centerRef.current.x;
        const canvasCenterY = rect.top + centerRef.current.y;
        
        const dx = mouseRef.current.x - canvasCenterX;
        const dy = mouseRef.current.y - canvasCenterY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        
        if (dist > 0) {
          const maxOffset = 15;
          eyeOffsetX = (dx / dist) * Math.min(maxOffset, dist * 0.05);
          eyeOffsetY = (dy / dist) * Math.min(maxOffset, dist * 0.05);
        }
      }
      
      // Draw glow effect when integrated
      if (phaseRef.current === 'integrated') {
        const gradient = ctx.createRadialGradient(
          centerRef.current.x + eyeOffsetX * 0.5,
          centerRef.current.y + eyeOffsetY * 0.5,
          0,
          centerRef.current.x,
          centerRef.current.y,
          size * 0.8
        );
        gradient.addColorStop(0, 'rgba(59, 130, 246, 0.15)');
        gradient.addColorStop(0.5, 'rgba(59, 130, 246, 0.05)');
        gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
        
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(centerRef.current.x, centerRef.current.y, size * 0.8, 0, Math.PI * 2);
        ctx.fill();
      }
      
      // Draw particles
      particlesRef.current.forEach((p, i) => {
        let x = p.x;
        let y = p.y;
        let alpha = p.alpha;
        
        const particlePhaseProgress = Math.max(0, cycleProgress - p.delay) / (1 - p.delay);
        
        if (phaseRef.current === 'integrated') {
          // Orbit slightly around origin + eye tracking
          const orbitRadius = 2;
          const orbitSpeed = 0.001 * time + i * 0.01;
          x = p.originX + Math.cos(orbitSpeed) * orbitRadius + eyeOffsetX;
          y = p.originY + Math.sin(orbitSpeed) * orbitRadius + eyeOffsetY;
          alpha = p.alpha;
        } else if (phaseRef.current === 'disintegrating') {
          // Explode outward
          const t = Math.min(1, (cycleProgress - 0.35) / 0.15);
          const easedT = easeOutCubic(t);
          
          x = p.originX + (p.targetX - p.originX) * easedT;
          y = p.originY + (p.targetY - p.originY) * easedT;
          alpha = p.alpha * (1 - easedT * 0.5);
          
          // Add some turbulence
          x += Math.sin(time * 0.003 + i) * 3 * easedT;
          y += Math.cos(time * 0.003 + i) * 3 * easedT;
        } else if (phaseRef.current === 'disintegrated') {
          // Float around dispersed
          x = p.targetX + Math.sin(time * 0.001 + i * 0.1) * 5;
          y = p.targetY + Math.cos(time * 0.001 + i * 0.1) * 5;
          alpha = p.alpha * 0.5;
        } else if (phaseRef.current === 'reintegrating') {
          // Come back together
          const t = Math.min(1, (cycleProgress - 0.65) / 0.35);
          const easedT = easeInOutCubic(t);
          
          const dispersedX = p.targetX + Math.sin(time * 0.001 + i * 0.1) * 5;
          const dispersedY = p.targetY + Math.cos(time * 0.001 + i * 0.1) * 5;
          
          x = dispersedX + (p.originX - dispersedX) * easedT;
          y = dispersedY + (p.originY - dispersedY) * easedT;
          alpha = p.alpha * (0.5 + easedT * 0.5);
        }
        
        // Update particle position
        p.x = x;
        p.y = y;
        
        // Draw particle
        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color.replace('rgb', 'rgba').replace(')', `, ${alpha})`);
        ctx.fill();
      });
      
      // Draw "eye" highlight when integrated
      if (phaseRef.current === 'integrated') {
        // Core glow
        const coreGradient = ctx.createRadialGradient(
          centerRef.current.x + eyeOffsetX,
          centerRef.current.y + eyeOffsetY,
          0,
          centerRef.current.x + eyeOffsetX,
          centerRef.current.y + eyeOffsetY,
          size * 0.15
        );
        coreGradient.addColorStop(0, 'rgba(200, 230, 255, 0.8)');
        coreGradient.addColorStop(0.5, 'rgba(100, 180, 255, 0.4)');
        coreGradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
        
        ctx.fillStyle = coreGradient;
        ctx.beginPath();
        ctx.arc(
          centerRef.current.x + eyeOffsetX,
          centerRef.current.y + eyeOffsetY,
          size * 0.15,
          0,
          Math.PI * 2
        );
        ctx.fill();
        
        // Small bright spot (pupil-like)
        ctx.beginPath();
        ctx.arc(
          centerRef.current.x + eyeOffsetX * 1.2,
          centerRef.current.y + eyeOffsetY * 1.2,
          4,
          0,
          Math.PI * 2
        );
        ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
        ctx.fill();
      }
      
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animationRef.current = requestAnimationFrame(animate);
    
    return () => {
      window.removeEventListener('resize', resizeCanvas);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [initParticles, size, cycleSpeed]);
  
  return (
    <canvas
      ref={canvasRef}
      className={cn('w-full h-full pointer-events-none', className)}
      style={{ opacity: 0.6 }}
    />
  );
}

// Easing functions
function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}

function easeInOutCubic(t: number): number {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

export default AnimatedOrb;
