// ============================================================================
// AnimatedOrb.tsx
// ANIMATED BLUE ORB WITH DISINTEGRATION EFFECT
// ============================================================================
// ✔ Ultra-smooth particle disintegration and reintegration
// ✔ Slow-motion physics engine
// ✔ Follows cursor direction when integrated
// ✔ Canvas-based particle system with high-precision easing
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
  randomFactor: number;
}

interface AnimatedOrbProps {
  className?: string;
  size?: number;
  particleCount?: number;
  cycleSpeed?: number; // Lower is slower
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function AnimatedOrb({
  className,
  size = 220,
  particleCount = 1000,
  cycleSpeed = 0.00015, // Significantly slowed down for grace
}: AnimatedOrbProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const animationRef = useRef<number | null>(null);
  const phaseRef = useRef<'integrated' | 'disintegrating' | 'disintegrated' | 'reintegrating'>('integrated');
  const phaseProgressRef = useRef(0);
  const mouseRef = useRef({ x: 0, y: 0 });
  const centerRef = useRef({ x: 0, y: 0 });
  
  // Initialize particles with spherical distribution
  const initParticles = useCallback(() => {
    const particles: Particle[] = [];
    const canvas = canvasRef.current;
    if (!canvas) return particles;
    
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    centerRef.current = { x: centerX, y: centerY };
    
    const radius = size / 2;
    
    for (let i = 0; i < particleCount; i++) {
      // Uniform distribution within a sphere (using cubic root for volume density)
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = radius * Math.cbrt(Math.random()); 
      
      const x = centerX + r * Math.sin(phi) * Math.cos(theta);
      const y = centerY + r * Math.sin(phi) * Math.sin(theta);
      
      // Deep blue/cyan aesthetic
      const blue = 180 + Math.floor(Math.random() * 75);
      const green = 100 + Math.floor(Math.random() * 60);
      const red = 40 + Math.floor(Math.random() * 40);
      
      const angle = Math.random() * Math.PI * 2;
      const speed = 0.3 + Math.random() * 1.2;
      
      particles.push({
        x,
        y,
        originX: x,
        originY: y,
        size: 0.8 + Math.random() * 2.2,
        color: `rgb(${red}, ${green}, ${blue})`,
        alpha: 0.3 + Math.random() * 0.7,
        velocity: { x: 0, y: 0 },
        angle,
        speed,
        // Target points for disintegration - wider spread
        targetX: x + Math.cos(angle) * (150 + Math.random() * 250),
        targetY: y + Math.sin(angle) * (150 + Math.random() * 250),
        delay: Math.random() * 0.4, // Staggered start
        randomFactor: Math.random() * 2,
      });
    }
    
    return particles;
  }, [size, particleCount]);
  
  // Track mouse for the "Look At" effect
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY };
    };
    
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);
  
  // Core Animation Logic
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;
    
    const resizeCanvas = () => {
      const parent = canvas.parentElement;
      if (parent) {
        canvas.width = parent.clientWidth;
        canvas.height = parent.clientHeight;
      } else {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
      }
      particlesRef.current = initParticles();
    };
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    let lastTime = 0;
    
    const animate = (time: number) => {
      const deltaTime = time - lastTime;
      lastTime = time;
      
      // Slowly increment global phase
      phaseProgressRef.current += cycleSpeed * deltaTime;
      const cycleProgress = phaseProgressRef.current % 1;
      
      /* PHASE TIMING:
         0.00 - 0.40: Integrated (Stable)
         0.40 - 0.55: Disintegrating (Explode)
         0.55 - 0.75: Disintegrated (Float)
         0.75 - 1.00: Reintegrating (Return)
      */
      
      if (cycleProgress < 0.40) {
        phaseRef.current = 'integrated';
      } else if (cycleProgress < 0.55) {
        phaseRef.current = 'disintegrating';
      } else if (cycleProgress < 0.75) {
        phaseRef.current = 'disintegrated';
      } else {
        phaseRef.current = 'reintegrating';
      }
      
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Interactive Offset Logic
      let eyeOffsetX = 0;
      let eyeOffsetY = 0;
      
      if (phaseRef.current === 'integrated' || phaseRef.current === 'reintegrating') {
        const rect = canvas.getBoundingClientRect();
        const canvasCenterX = rect.left + centerRef.current.x;
        const canvasCenterY = rect.top + centerRef.current.y;
        
        const dx = mouseRef.current.x - canvasCenterX;
        const dy = mouseRef.current.y - canvasCenterY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        
        if (dist > 0) {
          const maxOffset = 25;
          const strength = phaseRef.current === 'integrated' ? 1 : (cycleProgress - 0.75) / 0.25;
          eyeOffsetX = (dx / dist) * Math.min(maxOffset, dist * 0.08) * strength;
          eyeOffsetY = (dy / dist) * Math.min(maxOffset, dist * 0.08) * strength;
        }
      }
      
      // Background Radial Glow
      if (phaseRef.current !== 'disintegrated') {
        const glowAlpha = phaseRef.current === 'disintegrating' 
          ? 0.15 * (1 - (cycleProgress - 0.4) / 0.15)
          : phaseRef.current === 'reintegrating'
          ? 0.15 * ((cycleProgress - 0.75) / 0.25)
          : 0.15;

        if (glowAlpha > 0) {
          const gradient = ctx.createRadialGradient(
            centerRef.current.x + eyeOffsetX * 0.5,
            centerRef.current.y + eyeOffsetY * 0.5,
            0,
            centerRef.current.x,
            centerRef.current.y,
            size
          );
          gradient.addColorStop(0, `rgba(59, 130, 246, ${glowAlpha})`);
          gradient.addColorStop(0.6, `rgba(59, 130, 246, ${glowAlpha * 0.3})`);
          gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
          
          ctx.fillStyle = gradient;
          ctx.beginPath();
          ctx.arc(centerRef.current.x, centerRef.current.y, size, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      
      // Particle Rendering Loop
      particlesRef.current.forEach((p, i) => {
        let x = p.x;
        let y = p.y;
        let alpha = p.alpha;
        
        // 1. INTEGRATED STATE
        if (phaseRef.current === 'integrated') {
          const orbitRadius = 1.5;
          const orbitSpeed = time * 0.0006 + i * 0.05;
          x = p.originX + Math.cos(orbitSpeed) * orbitRadius + eyeOffsetX;
          y = p.originY + Math.sin(orbitSpeed) * orbitRadius + eyeOffsetY;
          alpha = p.alpha;
        } 
        
        // 2. DISINTEGRATING (EXPLODE)
        else if (phaseRef.current === 'disintegrating') {
          const t = (cycleProgress - 0.40) / 0.15;
          const easedT = easeOutQuart(Math.max(0, t - p.delay * 0.2));
          
          const targetX = p.targetX + Math.sin(time * 0.001 + i) * 10;
          const targetY = p.targetY + Math.cos(time * 0.001 + i) * 10;
          
          x = p.originX + (targetX - p.originX) * easedT + eyeOffsetX * (1 - easedT);
          y = p.originY + (targetY - p.originY) * easedT + eyeOffsetY * (1 - easedT);
          alpha = p.alpha * (1 - easedT * 0.6);
        } 
        
        // 3. DISINTEGRATED (FLOAT)
        else if (phaseRef.current === 'disintegrated') {
          const driftX = Math.sin(time * 0.0005 + i * 0.1) * 15;
          const driftY = Math.cos(time * 0.0005 + i * 0.1) * 15;
          x = p.targetX + driftX;
          y = p.targetY + driftY;
          alpha = p.alpha * 0.4;
        } 
        
        // 4. REINTEGRATING (RETURN)
        else if (phaseRef.current === 'reintegrating') {
          const t = (cycleProgress - 0.75) / 0.25;
          const easedT = easeInOutExpo(t);
          
          const currentDriftX = p.targetX + Math.sin(time * 0.0005 + i * 0.1) * 15;
          const currentDriftY = p.targetY + Math.cos(time * 0.0005 + i * 0.1) * 15;
          
          const destX = p.originX + eyeOffsetX;
          const destY = p.originY + eyeOffsetY;
          
          x = currentDriftX + (destX - currentDriftX) * easedT;
          y = currentDriftY + (destY - currentDriftY) * easedT;
          alpha = p.alpha * (0.4 + easedT * 0.6);
        }
        
        p.x = x;
        p.y = y;
        
        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color.replace('rgb', 'rgba').replace(')', `, ${alpha})`);
        ctx.fill();
      });
      
      // Core Highlights (Pupil/Eye Effect)
      if (phaseRef.current === 'integrated' || phaseRef.current === 'reintegrating') {
        const eyeAlpha = phaseRef.current === 'reintegrating' 
          ? easeInCubic((cycleProgress - 0.75) / 0.25) 
          : 1;

        if (eyeAlpha > 0.1) {
          // Inner Core
          const coreGradient = ctx.createRadialGradient(
            centerRef.current.x + eyeOffsetX,
            centerRef.current.y + eyeOffsetY,
            0,
            centerRef.current.x + eyeOffsetX,
            centerRef.current.y + eyeOffsetY,
            size * 0.2
          );
          coreGradient.addColorStop(0, `rgba(220, 240, 255, ${0.8 * eyeAlpha})`);
          coreGradient.addColorStop(0.4, `rgba(100, 180, 255, ${0.4 * eyeAlpha})`);
          coreGradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
          
          ctx.fillStyle = coreGradient;
          ctx.beginPath();
          ctx.arc(
            centerRef.current.x + eyeOffsetX,
            centerRef.current.y + eyeOffsetY,
            size * 0.2,
            0,
            Math.PI * 2
          );
          ctx.fill();
          
          // Glint
          ctx.beginPath();
          ctx.arc(
            centerRef.current.x + eyeOffsetX * 1.3,
            centerRef.current.y + eyeOffsetY * 1.3,
            size * 0.02,
            0,
            Math.PI * 2
          );
          ctx.fillStyle = `rgba(255, 255, 255, ${0.9 * eyeAlpha})`;
          ctx.fill();
        }
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
    <div className={cn("relative flex items-center justify-center overflow-hidden", className)}>
      <canvas
        ref={canvasRef}
        className="w-full h-full pointer-events-none transition-opacity duration-1000"
        style={{ opacity: 0.8 }}
      />
    </div>
  );
}

/* ============================================================================
   EASING FUNCTIONS (For High-Fidelity Motion)
============================================================================ */

function easeOutQuart(t: number): number {
  return 1 - Math.pow(1 - t, 4);
}

function easeInCubic(t: number): number {
  return t * t * t;
}

function easeInOutExpo(t: number): number {
  if (t === 0) return 0;
  if (t === 1) return 1;
  if ((t /= 0.5) < 1) return 0.5 * Math.pow(2, 10 * (t - 1));
  return 0.5 * (-Math.pow(2, -10 * --t) + 2);
}

export default AnimatedOrb;
