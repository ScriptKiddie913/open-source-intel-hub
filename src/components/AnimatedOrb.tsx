// ============================================================================
// AnimatedOrb.tsx
// ANIMATED BLUE ORB WITH SEAMLESS DISINTEGRATION & REINTEGRATION
// ============================================================================
// ✔ Ultra-slow cinematic disintegration
// ✔ Seamless phase blending (no jumps)
// ✔ Entropy-based particle dispersion
// ✔ Perfect reintegration symmetry
// ✔ Cursor-follow with damped inertia
// ✔ Canvas-based particle system
// ============================================================================

'use client';

import React, {
  useRef,
  useEffect,
  useState,
  useCallback,
} from 'react';
import { cn } from '@/lib/utils';

/* ============================================================================ */
/* TYPES */
/* ============================================================================ */

interface Particle {
  x: number;
  y: number;
  originX: number;
  originY: number;

  entropyX: number;
  entropyY: number;

  size: number;
  color: string;
  alpha: number;

  angle: number;
  speed: number;

  targetX: number;
  targetY: number;

  delay: number;

  driftSeed: number;
}

interface AnimatedOrbProps {
  className?: string;
  size?: number;
  particleCount?: number;
  cycleSpeed?: number;
}

/* ============================================================================ */
/* MAIN COMPONENT */
/* ============================================================================ */

export function AnimatedOrb({
  className,
  size = 200,
  particleCount = 800,
  cycleSpeed = 0.00012, // ⬅ MUCH SLOWER GLOBAL TIME
}: AnimatedOrbProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const animationRef = useRef<number | null>(null);

  const timeRef = useRef(0);
  const mouseRef = useRef({ x: 0, y: 0 });
  const smoothedMouseRef = useRef({ x: 0, y: 0 });
  const centerRef = useRef({ x: 0, y: 0 });

  /* ======================================================================== */
  /* PARTICLE INITIALIZATION */
  /* ======================================================================== */

  const initParticles = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return [];

    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    centerRef.current = { x: cx, y: cy };

    const radius = size / 2;
    const particles: Particle[] = [];

    for (let i = 0; i < particleCount; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = radius * Math.cbrt(Math.random());

      const ox = cx + r * Math.sin(phi) * Math.cos(theta);
      const oy = cy + r * Math.sin(phi) * Math.sin(theta);

      const angle = Math.random() * Math.PI * 2;
      const dist = 220 + Math.random() * 260;

      const blue = 160 + Math.floor(Math.random() * 90);
      const green = 90 + Math.floor(Math.random() * 70);

      particles.push({
        x: ox,
        y: oy,
        originX: ox,
        originY: oy,

        entropyX: ox,
        entropyY: oy,

        size: 1 + Math.random() * 2.5,
        color: `rgb(${20 + Math.random() * 40}, ${green}, ${blue})`,
        alpha: 0.45 + Math.random() * 0.55,

        angle,
        speed: 0.2 + Math.random() * 0.8,

        targetX: ox + Math.cos(angle) * dist,
        targetY: oy + Math.sin(angle) * dist,

        delay: Math.random(),
        driftSeed: Math.random() * 1000,
      });
    }

    return particles;
  }, [particleCount, size]);

  /* ======================================================================== */
  /* MOUSE TRACKING WITH INERTIA */
  /* ======================================================================== */

  useEffect(() => {
    const move = (e: MouseEvent) => {
      mouseRef.current.x = e.clientX;
      mouseRef.current.y = e.clientY;
    };
    window.addEventListener('mousemove', move);
    return () => window.removeEventListener('mousemove', move);
  }, []);

  /* ======================================================================== */
  /* ANIMATION LOOP */
  /* ======================================================================== */

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      particlesRef.current = initParticles();
    };

    resize();
    window.addEventListener('resize', resize);

    const animate = (t: number) => {
      timeRef.current += cycleSpeed;
      const time = timeRef.current;

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      /* -------------------------------------------------------------------- */
      /* GLOBAL SEAMLESS PHASE CURVE (0 → 1 → 0) */
      /* -------------------------------------------------------------------- */

      const phase = 0.5 - 0.5 * Math.cos(time * Math.PI * 2);

      const disintegration = smoothstep(0.25, 0.55, phase);
      const reintegration = smoothstep(0.55, 0.9, phase);

      const entropy = disintegration * (1 - reintegration);

      /* -------------------------------------------------------------------- */
      /* MOUSE INERTIA */
      /* -------------------------------------------------------------------- */

      smoothedMouseRef.current.x +=
        (mouseRef.current.x - smoothedMouseRef.current.x) * 0.02;
      smoothedMouseRef.current.y +=
        (mouseRef.current.y - smoothedMouseRef.current.y) * 0.02;

      const rect = canvas.getBoundingClientRect();
      const dx =
        smoothedMouseRef.current.x -
        (rect.left + centerRef.current.x);
      const dy =
        smoothedMouseRef.current.y -
        (rect.top + centerRef.current.y);

      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const maxOffset = 18;

      const eyeX = (dx / dist) * Math.min(maxOffset, dist * 0.04);
      const eyeY = (dy / dist) * Math.min(maxOffset, dist * 0.04);

      /* -------------------------------------------------------------------- */
      /* GLOW */
      /* -------------------------------------------------------------------- */

      const glow = ctx.createRadialGradient(
        centerRef.current.x + eyeX * 0.4,
        centerRef.current.y + eyeY * 0.4,
        0,
        centerRef.current.x,
        centerRef.current.y,
        size * 0.9
      );

      glow.addColorStop(0, `rgba(59,130,246,${0.12 * (1 - entropy)})`);
      glow.addColorStop(1, 'rgba(59,130,246,0)');

      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(
        centerRef.current.x,
        centerRef.current.y,
        size * 0.9,
        0,
        Math.PI * 2
      );
      ctx.fill();

      /* -------------------------------------------------------------------- */
      /* PARTICLES */
      /* -------------------------------------------------------------------- */

      particlesRef.current.forEach((p, i) => {
        const drift =
          Math.sin(time * 0.4 + p.driftSeed) * 6 * entropy;

        const tx =
          p.originX +
          (p.targetX - p.originX) * entropy +
          Math.cos(p.angle) * drift;

        const ty =
          p.originY +
          (p.targetY - p.originY) * entropy +
          Math.sin(p.angle) * drift;

        p.entropyX += (tx - p.entropyX) * 0.015;
        p.entropyY += (ty - p.entropyY) * 0.015;

        const x =
          p.entropyX +
          eyeX * (1 - entropy) * 0.8;
        const y =
          p.entropyY +
          eyeY * (1 - entropy) * 0.8;

        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color.replace(
          'rgb',
          'rgba'
        ).replace(')', `, ${p.alpha * (1 - entropy * 0.4)})`);
        ctx.fill();
      });

      /* -------------------------------------------------------------------- */
      /* CORE */
      /* -------------------------------------------------------------------- */

      const core = ctx.createRadialGradient(
        centerRef.current.x + eyeX,
        centerRef.current.y + eyeY,
        0,
        centerRef.current.x + eyeX,
        centerRef.current.y + eyeY,
        size * 0.18
      );

      core.addColorStop(0, 'rgba(210,240,255,0.85)');
      core.addColorStop(1, 'rgba(59,130,246,0)');

      ctx.fillStyle = core;
      ctx.beginPath();
      ctx.arc(
        centerRef.current.x + eyeX,
        centerRef.current.y + eyeY,
        size * 0.18,
        0,
        Math.PI * 2
      );
      ctx.fill();

      animationRef.current = requestAnimationFrame(animate);
    };

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('resize', resize);
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, [initParticles, cycleSpeed, size]);

  return (
    <canvas
      ref={canvasRef}
      className={cn('w-full h-full pointer-events-none', className)}
      style={{ opacity: 0.65 }}
    />
  );
}

/* ============================================================================ */
/* UTILS */
/* ============================================================================ */

function smoothstep(a: number, b: number, t: number) {
  const x = Math.min(1, Math.max(0, (t - a) / (b - a)));
  return x * x * (3 - 2 * x);
}

export default AnimatedOrb;
